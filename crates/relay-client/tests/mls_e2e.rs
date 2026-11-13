//! 묶음 22 MLS 를 실제 relay 와 연결 루프로(§3·§7): KeyPackage 올리기·채우기, 두 기기 왕복.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use lodelai_crypto::DeviceKeys;
use lodelai_effects::{Clock, IdGen, OsRng, UnixMillis};
use lodelai_relay::{bind_local, db::Db, serve, App, Config as RelayConfig, Effects, Relay};
use lodelai_relay_client::mls::Provider;
use lodelai_relay_client::mls_conn::KP_PUBLISHED;
use lodelai_relay_client::mls_store::MlsStore;
use lodelai_relay_client::register::{register_device, DeviceInfo};
use lodelai_relay_client::{Config, Inbound, Outgoing, RelayClient, SendWaitReason};
use lodelai_testkit::effects::TestEffects;
use openmls_traits::OpenMlsProvider as _;
use serde_json::{json, Value};
use tokio::sync::mpsc::Receiver;
use zeroize::Zeroizing;

const TOKEN: &str = "reg-token";
const SERVER: &str = "local";
const START_MS: i64 = 1_792_728_776_000;
const KPS: usize = 4;

/// 한 번에 도는 시험 수 — 시험마다 relay·기기 서넛·debug 빌드 KeyPackage 만들기라, 부하 큰 장비에서 전부 나란히 돌면 시간 초과가
/// 난다(4개씩이면 안정).
static SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

struct Harness {
    _slot: tokio::sync::SemaphorePermit<'static>,
    addr: SocketAddr,
    fx: TestEffects,
    app: App,
    dir: tempfile::TempDir,
}

async fn relay() -> Harness {
    relay_with(true).await
}

/// `groups` = relay 실행 파일의 그룹 켬(22 §12-30 — 끄면 101 `Lodelai-Features` 에 groups 가 없고, 그룹 시작은 unroutable).
async fn relay_with(groups: bool) -> Harness {
    relay_cfg(groups, |_| {}).await
}

/// [`relay_with`] 에 relay 설정을 더 고쳐서.
async fn relay_cfg(groups: bool, f: impl FnOnce(&mut RelayConfig)) -> Harness {
    // `RUST_LOG` 를 주면 relay·클라이언트 로그를 stderr 로(사냥). 안 주면 info 이상을 시험 출력에 담는다 — libtest 는 실패한
    // 시험의 출력만 보이므로 간헐 실패 판의 로그(연결 루프 갈래가 오래 걸림·물러섬 등)가 그 판에 남는다(#821). 시험 안에서 만든
    // tokio 일꾼 스레드는 그 시험의 출력 잡기를 물려받는다.
    if std::env::var_os("RUST_LOG").is_some() {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
            .with_writer(std::io::stderr)
            .try_init();
    } else {
        let _ = tracing_subscriber::fmt()
            .with_env_filter(tracing_subscriber::EnvFilter::new(
                "lodelai_relay_client=info,lodelai_relay=info",
            ))
            .with_ansi(false)
            .with_test_writer()
            .try_init();
    }
    let slot = SLOTS.acquire().await.unwrap();
    // openmls 는 KeyPackage 수명을 실제 시계로 찍는다 — 받는 쪽 수명 검사가 맞게 가짜 시계도 지금에서 시작.
    let fx = TestEffects::new(lodelai_effects::SystemClock.now().0.max(START_MS), 3);
    let dir = tempfile::tempdir().unwrap();
    let (listener, addr) = bind_local(0).await.unwrap();
    let mut config = RelayConfig::local(SERVER);
    config.blob_dir = Some(dir.path().join("relay-blobs"));
    config.blob_min_free = 0;
    config.port = addr.port();
    config.registration_token = Some(TOKEN.into());
    config.groups = groups;
    f(&mut config);
    let effects = Effects {
        clock: fx.clock.clone(),
        ids: fx.ids.clone(),
        rng: fx.rng.clone(),
    };
    let app = Relay::with_mailer(
        config,
        effects,
        {
            // 실제 relay 는 email 키가 늘 있다(원격은 필수, 로컬은 무작위) — contact_link 가 쓴다.
            let db = Db::open(&dir.path().join("relay.db")).unwrap();
            db.set_email_key(b"test-email-hmac-key-0123456789abcdef".to_vec());
            db
        },
        None,
    );
    tokio::spawn(serve(app.clone(), listener));
    Harness {
        _slot: slot,
        addr,
        fx,
        app,
        dir,
    }
}

fn relay_sql(h: &Harness, sql: &str) {
    let c = rusqlite::Connection::open(h.dir.path().join("relay.db")).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    c.execute_batch(sql).unwrap();
}

/// relay DB 의 정수 하나(없으면 0).
fn relay_i64(h: &Harness, sql: &str) -> i64 {
    let c = rusqlite::Connection::open(h.dir.path().join("relay.db")).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    c.query_row(sql, [], |r| r.get::<_, Option<i64>>(0))
        .unwrap()
        .unwrap_or(0)
}

/// relay DB 값이 `want` 이상이 될 때까지(최대 10초).
async fn until_relay(h: &Harness, sql: &str, want: i64) {
    for _ in 0..100 {
        if relay_i64(h, sql) >= want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("{sql} 가 {want} 에 닿지 않음 (지금 {})", relay_i64(h, sql));
}

fn store_key(seed: u8) -> Zeroizing<[u8; 32]> {
    Zeroizing::new([seed; 32])
}

/// #846: 꺼진 멤버의 저장에서 그 그룹을 막힘으로(`on`) 두거나 푼다 — 켜면 막힌 멤버는 붙은 채 Commit 마다 commit_fail 만 낸다.
/// 연결된 투표자가 없으면 relay 가 Commit 을 배달 직후 확정하므로, 무효 장면은 '연결된 투표자의 fail'로 만든다.
fn stall(h: &Harness, db: &str, seed: u8, gid: &str, on: bool) {
    let s = MlsStore::open(&h.dir.path().join(db), &store_key(seed), Arc::new(OsRng)).unwrap();
    if on {
        s.set_state(
            gid.as_bytes(),
            lodelai_relay_client::mls_store::GroupState::StalledServer,
            "test",
            1,
        )
        .unwrap();
    } else {
        s.clear_state(gid.as_bytes()).unwrap();
    }
}

/// relay 에 그 사용자의 fail 표가 남을 때까지.
async fn until_fail(h: &Harness, gid: &str, user: &str) {
    until_relay(
        h,
        &format!("SELECT COUNT(*) FROM mls_votes WHERE group_id = '{gid}' AND user = '{user}' AND fail = 1"),
        1,
    )
    .await;
}

impl Harness {
    async fn user(&self, name: &str, seed: u8) -> DeviceKeys {
        let keys = DeviceKeys::generate(&[seed; 64]);
        register_device(self.addr, TOKEN, &DeviceInfo::of(name, Some(name), &keys))
            .await
            .unwrap();
        keys
    }

    fn start(
        &self,
        user: &str,
        keys: &DeviceKeys,
        seed: u8,
        db: &str,
    ) -> (RelayClient, Receiver<Inbound>) {
        self.start_groups(user, keys, seed, db, true)
    }

    fn start_groups(
        &self,
        user: &str,
        keys: &DeviceKeys,
        seed: u8,
        db: &str,
        groups: bool,
    ) -> (RelayClient, Receiver<Inbound>) {
        self.start_with(user, keys, seed, db, |c| c.groups = groups)
    }

    fn start_with(
        &self,
        user: &str,
        keys: &DeviceKeys,
        seed: u8,
        db: &str,
        f: impl FnOnce(&mut Config),
    ) -> (RelayClient, Receiver<Inbound>) {
        let mut c = Config::new(
            format!("ws://127.0.0.1:{}/v1/ws", self.addr.port()),
            SERVER,
            user,
            keys.clone(),
            store_key(seed),
        );
        c.send_interval = Duration::from_millis(5);
        c.backoff_max = Duration::from_millis(200);
        // 시험이 나란히 돌 때 debug 빌드의 KeyPackage 100개 만들기가 느려 시간 초과가 난다 — 작게.
        c.key_package_target = KPS;
        c.groups = true;
        f(&mut c);
        let clock: Arc<dyn Clock> = self.fx.clock.clone();
        RelayClient::start(c, &self.dir.path().join(db), clock, self.fx.rng.clone()).unwrap()
    }

    /// 코어가 만드는 서명 전 chat(꼴은 relay-client `envelope::chat` 한 벌).
    fn chat(&self, from: &str, to: &str, text: &str) -> Value {
        let now = self.fx.clock.now();
        lodelai_relay_client::envelope::chat(
            &self.fx.ids.next_ulid(),
            now,
            UnixMillis(now.0 + 86_400_000),
            from,
            to,
            text,
        )
    }
}

/// 받은 chat 의 평문(그 사이 것은 ack 하고 버린다).
async fn got_text(rx: &mut Receiver<Inbound>) -> String {
    let Inbound::Deliver { message, ack } =
        wait(rx, "deliver", |i| matches!(i, Inbound::Deliver { .. })).await
    else {
        unreachable!()
    };
    ack.ack();
    assert_eq!(
        message.pointer("/body/enc").and_then(Value::as_str),
        Some("plain")
    );
    message
        .pointer("/body/text")
        .and_then(Value::as_str)
        .unwrap()
        .to_owned()
}

async fn wait(rx: &mut Receiver<Inbound>, what: &str, f: impl Fn(&Inbound) -> bool) -> Inbound {
    // 시험이 나란히 돌고 relay DB 가 파일이라(org_left 시험의 SQL) 느릴 때가 있다. 다른 세션 빌드와 겹친 전체 검사에서는 15초도
    // 넘었다(#536) — 조건 대기라 상한만 넉넉히, 시간 초과면 그 사이 받은 것을 찍는다.
    let t0 = std::time::Instant::now();
    let mut seen = Vec::new();
    tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            let i = rx.recv().await.expect("채널 닫힘");
            if f(&i) {
                return i;
            }
            seen.push(format!("{:?} {:.120?}", t0.elapsed(), i));
        }
    })
    .await
    .unwrap_or_else(|_| panic!("{what} 를 기다리다 시간 초과 — 그 사이 받은 것: {seen:#?}"))
}

/// ready 와 첫 디렉터리(디렉터리 답이 오면 첫 KeyPackage 묶음은 relay 가 처리했다).
async fn ready(rx: &mut Receiver<Inbound>) {
    wait(rx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    wait(rx, "directory", |i| matches!(i, Inbound::Directory(_))).await;
}

/// 첫 접속에 보통 100 + 마지막 수단을 올리고 표시를 남긴다 — 다시 접속해도 다시 올리지 않는다(올리면 relay 상한에 걸림).
/// 접속 뒤 그 기기가 내 저장소에 들어올 때까지(directory 처리 — `Ready` 는 directory 보다 먼저 나간다). 상한 5초.
async fn until_peer(c: &RelayClient, device_id: &str) {
    for _ in 0..100 {
        if c.store().peer(device_id).unwrap().is_some() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    panic!("5초 안에 저장소에 {device_id} 가 들어오지 않음");
}

#[tokio::test(flavor = "multi_thread")]
async fn 첫_접속에_keypackage_를_올리고_다시_올리지_않는다() {
    let h = relay().await;
    let k = h.user("alice", 1).await;
    let dev = k.device_id().as_str().to_owned();
    let (c, mut rx) = h.start("alice", &k, 1, "a.db");
    ready(&mut rx).await;
    assert_eq!(h.app.db.kp_state(&dev).unwrap(), (KPS as u64, true));
    c.shutdown().await;

    let mls = Provider::new(
        MlsStore::open(&h.dir.path().join("a.db"), &store_key(1), Arc::new(OsRng)).unwrap(),
    );
    assert!(mls.storage().flag(KP_PUBLISHED).unwrap());
    drop(mls);

    let (c, mut rx) = h.start("alice", &k, 1, "a.db");
    ready(&mut rx).await;
    assert_eq!(h.app.db.kp_state(&dev).unwrap(), (KPS as u64, true));
    c.shutdown().await;
}

/// 두 기기 왕복: 처음 보내는 쪽이 pair 그룹을 만들고(KeyPackage 가져오기 → 시작 → Add Commit), 상대는 Welcome 으로 들어가
/// 응용 메시지를 연다. 그 뒤 반대 방향도 같은 그룹으로.
#[tokio::test(flavor = "multi_thread")]
async fn pair_그룹을_만들어_양쪽으로_주고받는다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;

    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "안녕 밥"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "안녕 밥");

    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "안녕 앨리스"),
    })
    .unwrap();
    assert_eq!(got_text(&mut arx).await, "안녕 앨리스");

    // 보낸 쪽은 relay ack 를 받는다(MLS 응용 메시지가 relay 검사를 지났다).
    wait(&mut brx, "ack", |i| matches!(i, Inbound::Ack { .. })).await;
    alice.shutdown().await;
    bob.shutdown().await;
}

/// 양쪽이 동시에 처음 보낸다: 한쪽의 시작은 `epoch_taken` — 그쪽은 자기 그룹을 버리고 상대 Welcome 으로 들어가 같은 평문을 보낸다.
#[tokio::test(flavor = "multi_thread")]
async fn 동시에_시작하면_진_쪽이_welcome_으로_들어가_보낸다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;

    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "먼저 A"),
        })
        .unwrap();
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "먼저 B"),
    })
    .unwrap();
    assert_eq!(got_text(&mut brx).await, "먼저 A");
    assert_eq!(got_text(&mut arx).await, "먼저 B");
    alice.shutdown().await;
    bob.shutdown().await;
}

/// 묶음 22 §9: 막힌 대화는 접속마다 코어에 다시 알린다(코어는 저장하지 않는다) — 처음 버린 글의 때(lost_since)와 함께.
#[tokio::test(flavor = "multi_thread")]
async fn 막힌_대화는_접속마다_다시_알린다() {
    use lodelai_relay_client::mls_store::GroupState;
    let h = relay().await;
    let k = h.user("alice", 1).await;
    let (c, mut rx) = h.start("alice", &k, 1, "a.db");
    ready(&mut rx).await;
    c.shutdown().await;
    let gid = lodelai_relay_client::mls::pair_group_id("alice", "bob");
    {
        let st =
            MlsStore::open(&h.dir.path().join("a.db"), &store_key(1), Arc::new(OsRng)).unwrap();
        st.set_conv(&gid, "bob@local").unwrap();
        st.set_state(&gid, GroupState::StalledDevice, "test", 1)
            .unwrap();
        st.put_lost(&gid, 5).unwrap();
        st.put_lost(&gid, 9).unwrap();
    }
    let (_c, mut rx) = h.start("alice", &k, 1, "a.db");
    let got = wait(&mut rx, "conversation sync", |i| {
        matches!(i, Inbound::ConversationSync { .. })
    })
    .await;
    let Inbound::ConversationSync {
        conversation,
        state,
        lost_since,
    } = got
    else {
        unreachable!()
    };
    assert_eq!(
        (conversation.as_str(), state, lost_since),
        ("bob@local", Some(GroupState::StalledDevice), Some(5)),
        "막힌 동안 처음 버린 때(§12-23 ③)"
    );
}

/// 그룹 변경 메시지(코어 group_change_out 꼴): kind group, `+gid` 앞, group_op·subject?·subjects?·base_seq 0, 본문 {op, name?}.
fn gchange(
    h: &Harness,
    from: &str,
    gid: &str,
    op: &str,
    subjects: &[&str],
    name: Option<&str>,
) -> Value {
    let now = h.fx.clock.now();
    lodelai_relay_client::envelope::group_change(
        &h.fx.ids.next_ulid(),
        now,
        UnixMillis(now.0 + 86_400_000),
        from,
        &format!("+{gid}@{SERVER}"),
        op,
        subjects,
        name,
    )
}

/// 묶음 22 §12-27 ⓒ: 내 사람 op 변경은 봉인할 때 GroupChangePending{Waiting}, 확정되면 같은 change_id(처음 보낸 msg_id)로
/// Final{seq} — 같은 확정의 GroupUpdate 보다 먼저 온다(코어가 기다린 줄에 seq 를 채워 줄을 두 번 넣지 않게).
#[tokio::test(flavor = "multi_thread")]
async fn 내_변경은_기다림_뒤_확정이_groupupdate_보다_먼저() {
    use lodelai_relay_client::ChangePending as P;
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let m = gchange(
        &h,
        "alice@local",
        &gid,
        "create",
        &["bob@local"],
        Some("팀"),
    );
    let id = m["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: m })
        .unwrap();
    let mut seen = Vec::new();
    loop {
        let i = wait(&mut arx, "기다림·확정·GroupUpdate", |i| {
            matches!(
                i,
                Inbound::GroupChangePending { .. } | Inbound::GroupUpdate { .. }
            )
        })
        .await;
        match i {
            Inbound::GroupChangePending {
                change_id,
                pending,
                seq,
            } => seen.push((change_id, pending, seq)),
            Inbound::GroupUpdate { seq, op, .. } => {
                assert_eq!((seq, op.as_str()), (2, "create"));
                break;
            }
            _ => unreachable!(),
        }
    }
    assert_eq!(
        seen,
        vec![(id.clone(), P::Waiting, None), (id, P::Final, Some(2))]
    );
}

/// 묶음 22 h1·§12-22: 만든 사람이 start 뒤 처음 멤버를 create Commit 하나로 넣는다 — 바로 확정(seq 2)되고 모두 GroupUpdate 를
/// 받는다. 그 뒤 그룹 글이 두 멤버 모두에게 열린다.
#[tokio::test(flavor = "multi_thread")]
async fn 그룹을_만들고_처음_멤버에게_글이_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        let u = wait(rx, &format!("{who} GroupUpdate"), |i| {
            matches!(i, Inbound::GroupUpdate { .. })
        })
        .await;
        let Inbound::GroupUpdate {
            gid: g,
            seq,
            op,
            state,
            ..
        } = u
        else {
            unreachable!()
        };
        assert_eq!(
            (g.as_str(), seq, op.as_str()),
            (gid.as_str(), 2, "create"),
            "{who}"
        );
        let mut members = state.members.clone();
        members.sort();
        assert_eq!(
            members,
            ["alice@local", "bob@local", "carol@local"],
            "{who}"
        );
        assert_eq!(state.admins, ["alice@local"], "{who}");
    }
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "모두 안녕"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "모두 안녕");
    assert_eq!(got_text(&mut crx).await, "모두 안녕");
}

/// 묶음 22 h1: 만든 뒤의 add 는 기존 멤버가 commit_ack 해야 확정된다(§4-7) — 확정되면 모두(새 멤버 포함) GroupUpdate add, 새 멤버는
/// Welcome 으로 들어와 그 뒤 글을 연다.
#[tokio::test(flavor = "multi_thread")]
async fn 만든_뒤_add_는_멤버_확인으로_확정된다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut drx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for rx in [&mut arx, &mut brx] {
        wait(
            rx,
            "create",
            |i| matches!(i, Inbound::GroupUpdate { op, .. } if op == "create"),
        )
        .await;
    }
    let mut add = gchange(&h, "alice@local", &gid, "add", &[], None);
    add["subject"] = json!("dave@local");
    add["body"] =
        json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    // relay 의 표 창(60초)을 넘기고, bob 의 commit_ack 가 늦게 와도 확정되게 몇 번 돌린다(나란히 도는 시험의 부하).
    // 표 창은 Commit 이 배달된 때부터라 그 뒤 시계를 넘겨야 한다 — 배달·ack 가 언제 끝날지 몰라 조금씩 되풀이.
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.fx.clock.advance(61_000);
        h.app.expire_tick();
    }
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("dave", &mut drx)] {
        let u = wait(
            rx,
            &format!("{who} add"),
            |i| matches!(i, Inbound::GroupUpdate { op, .. } if op == "add"),
        )
        .await;
        let Inbound::GroupUpdate {
            seq,
            subject,
            state,
            ..
        } = u
        else {
            unreachable!()
        };
        // seq 2 create, 3 처음 이름 rename(§12-23), 4 add.
        assert_eq!((seq, subject.as_deref()), (4, Some("dave@local")), "{who}");
        assert_eq!(state.members.len(), 3, "{who}");
    }
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "어서 와"),
        })
        .unwrap();
    assert_eq!(got_text(&mut drx).await, "어서 와");
    assert_eq!(got_text(&mut brx).await, "어서 와");
}

/// §7-47: add 를 낸 기기가 확정 뒤 이름 다시 보내기(rename)에 그 add 의 history 를 얹는다 — 새 멤버는 그 값(든 뒤 처음 하나)을
/// GroupState.history_hidden 으로, 옛 꼴 add(history 없음)로 든 멤버는 None. 이름을 이미 아는 멤버는 history 실린 rename 으로
/// 이름을 바꾸지 않는다(줄 없음). rename 은 멤버 누구나라 관리자 아님이 낸 add 도 같다(relay db.rs group_app_op_now).
#[tokio::test(flavor = "multi_thread")]
async fn add_의_history_는_새_멤버에게만_한_번() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let dk = h.user("dave", 4).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    let (dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    for rx in [&mut arx, &mut brx, &mut crx, &mut drx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx)] {
        update_of(rx, who, "create").await;
    }
    update_of(&mut brx, "bob", "rename").await;
    let add = |who: &str, history: Option<bool>| {
        let mut a = gchange(&h, "alice@local", &gid, "add", &[], None);
        a["subject"] = json!(who);
        let mut asked = json!({"op": "add", "subject": who});
        if let Some(x) = history {
            asked["history"] = json!(x);
        }
        a["body"] = json!({"enc": "plain", "text": asked.to_string()});
        a
    };
    let tick = || async {
        for _ in 0..30 {
            tokio::time::sleep(Duration::from_millis(100)).await;
            h.fx.clock.advance(61_000);
            h.app.expire_tick();
        }
    };
    alice
        .enqueue(&Outgoing::GroupChange {
            message: add("carol@local", Some(true)),
        })
        .unwrap();
    tick().await;
    let (_, st) = update_of(&mut crx, "carol", "add").await;
    assert_eq!(st.history_hidden, None, "rename 전엔 값이 없다");
    let (_, st) = update_of(&mut crx, "carol", "rename").await;
    assert_eq!(
        (st.name.as_str(), st.history_hidden),
        ("팀", Some(true)),
        "이름도 처음 알고 history 도"
    );
    assert_eq!(
        carol.group(&gid).unwrap().unwrap().history_hidden,
        Some(true)
    );
    // 옛 꼴 add(history 없음) — dave 는 이름만, 값 없음.
    alice
        .enqueue(&Outgoing::GroupChange {
            message: add("dave@local", None),
        })
        .unwrap();
    tick().await;
    let (_, st) = update_of(&mut drx, "dave", "rename").await;
    assert_eq!((st.name.as_str(), st.history_hidden), ("팀", None));
    assert_eq!(dave.group(&gid).unwrap().unwrap().history_hidden, None);
    // 이름을 아는 bob 은 history 실린 rename 으로 줄이 생기지 않는다(같은 이름) — 다음 rename 은 carol 이 낸 진짜 바꿈.
    let rn = gchange(&h, "carol@local", &gid, "rename", &[], Some("새 팀"));
    carol
        .enqueue(&Outgoing::GroupChange { message: rn })
        .unwrap();
    let (_, st) = update_of(&mut brx, "bob", "rename").await;
    assert_eq!(st.name, "새 팀", "bob 이 받은 다음 rename 은 carol 의 바꿈");
    assert_eq!(st.history_hidden, None, "bob 의 값은 없다(다른 subject)");
    // carol 의 값은 그대로(두 번째 값 없음 — 이름 바꾸기는 history 를 건드리지 않는다).
    let (_, st) = update_of(&mut crx, "carol", "rename").await;
    assert_eq!((st.name.as_str(), st.history_hidden), ("새 팀", Some(true)));
}

/// 묶음 22 h1: 만든 사람의 다른 기기도 create Commit 에 같이 들어간다(내 다른 기기 잎) — 그 기기도 GroupUpdate 를 받고, 거기서
/// 보낸 글이 상대와 만든 기기 모두에 열린다.
#[tokio::test(flavor = "multi_thread")]
async fn 만든_사람의_다른_기기도_그룹에_들어간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    ready(&mut arx).await;
    // 내 다른 기기는 연결 코드로 승인(심기) 뒤 등록 — a1 이 devcert 를 서명해 올려야 a2 가 잎 자격을 얻는다(§2b 3).
    let a2k = DeviceKeys::generate(&[5; 64]);
    let a2 = DeviceInfo::of("alice", None, &a2k);
    alice.plant_own_device(&a2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &a2, true)
        .await
        .unwrap();
    let signer = format!("\"signer\":\"{}\"", ak.device_id().as_str());
    wait(
        &mut arx,
        "a2 devcert",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&signer)),
    )
    .await;
    let (alice2, mut a2rx) = h.start("alice", &a2k, 5, "a2.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut a2rx).await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.fx.clock.advance(61_000);
        h.app.expire_tick();
    }
    for (who, rx) in [("a1", &mut arx), ("a2", &mut a2rx), ("bob", &mut brx)] {
        let u = wait(
            rx,
            &format!("{who} create"),
            |i| matches!(i, Inbound::GroupUpdate { op, .. } if op == "create"),
        )
        .await;
        let Inbound::GroupUpdate { state, .. } = u else {
            unreachable!()
        };
        let mut members = state.members.clone();
        members.sort();
        assert_eq!(members, ["alice@local", "bob@local"], "{who}");
    }
    alice2
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "다른 기기에서"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "다른 기기에서");
    assert_eq!(got_text(&mut arx).await, "다른 기기에서");
}

/// relay 표 창(60초)을 넘겨 멤버 commit_ack 로 확정되게 시계를 조금씩 돌린다.
async fn settle(h: &Harness) {
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        h.fx.clock.advance(61_000);
        h.app.expire_tick();
    }
}

/// 시험 동안 계속 relay 표 창을 넘기는 시계(끝나면 abort). 다시 만들어진 Commit 도 확정되게.
fn ticker(h: &Harness) -> tokio::task::JoinHandle<()> {
    let (clock, app) = (h.fx.clock.clone(), h.app.clone());
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(Duration::from_millis(100)).await;
            clock.advance(61_000);
            app.expire_tick();
        }
    })
}

async fn update_of(
    rx: &mut Receiver<Inbound>,
    who: &str,
    want: &str,
) -> (u64, lodelai_relay_client::GroupState) {
    let u = wait(
        rx,
        &format!("{who} {want}"),
        |i| matches!(i, Inbound::GroupUpdate { op, .. } if op == want),
    )
    .await;
    let Inbound::GroupUpdate { seq, state, .. } = u else {
        unreachable!()
    };
    (seq, state)
}

/// 묶음 22 h2: 관리자 넘기기(GCE)·내보내기(관리자 remove)·나가기(app → 남은 기기 leave
/// Commit) — 모두 MLS 로, 빠진 사람에게는 그 뒤 글이 가지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 관리자_내보내기_나가기() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let to = format!("+{gid}@{SERVER}");
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    // 관리자 넘기기: alice 가 carol 을 관리자로.
    let mut adm = gchange(&h, "alice@local", &gid, "admin", &[], None);
    adm["subject"] = json!("carol@local");
    alice
        .enqueue(&Outgoing::GroupChange { message: adm })
        .unwrap();
    settle(&h).await;
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        let (_, st) = update_of(rx, who, "admin").await;
        let mut a = st.admins.clone();
        a.sort();
        assert_eq!(a, ["alice@local", "carol@local"], "{who}");
    }

    // 내보내기: alice(관리자)가 bob 을.
    let mut rm = gchange(&h, "alice@local", &gid, "remove", &[], None);
    rm["subject"] = json!("bob@local");
    alice
        .enqueue(&Outgoing::GroupChange { message: rm })
        .unwrap();
    settle(&h).await;
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        let (_, st) = update_of(rx, who, "remove").await;
        let mut mm = st.members.clone();
        mm.sort();
        assert_eq!(mm, ["alice@local", "carol@local"], "{who}");
    }
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &to, "bob 없이"),
        })
        .unwrap();
    assert_eq!(got_text(&mut crx).await, "bob 없이");
    // 내보내진 bob 은 그룹이 없다 — 보낼 수 없다.
    assert!(matches!(
        bob.group_send_check(&gid),
        Err(lodelai_relay_client::Error::NotGroupMember)
    ));

    // 나가기: carol 이 app 으로 알리면 relay 가 표에서 빼고 alice 기기가 leave Commit 으로 잎을 뺀다.
    let mut lv = gchange(&h, "carol@local", &gid, "leave", &[], None);
    lv["body"] = json!({"enc": "plain", "text": json!({"op": "leave"}).to_string()});
    carol
        .enqueue(&Outgoing::GroupChange { message: lv })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("carol", &mut crx)] {
        let (_, st) = update_of(rx, who, "leave").await;
        assert!(!st.members.contains(&"carol@local".to_owned()), "{who}");
    }
    settle(&h).await;
    // alice 혼자 남은 그룹 — 잎도 alice 뿐.
    let mut alone = false;
    for _ in 0..50 {
        if alice.group_send_check(&gid).unwrap_or(0) == 0 {
            alone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(alone, "carol 잎이 빠지지 않음");
}

/// 묶음 22 h2·§12-23: 처음 이름은 만든 기기가 create 확정 뒤 rename 으로, 멤버의 rename 은 모두에게(이름은 MLS 평문 머리에만).
#[tokio::test(flavor = "multi_thread")]
async fn 이름은_rename_으로() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    // 처음 이름은 만든 기기가 확정 뒤 rename 으로 보낸다.
    for (who, rx) in [("bob", &mut brx), ("carol", &mut crx)] {
        let (_, st) = update_of(rx, who, "rename").await;
        assert_eq!(st.name, "팀", "{who}");
    }

    // 이름 바꾸기: 멤버 carol. app 이라 ack 가 확정 — carol 에게 그 줄 키로 Final{seq} 가 GroupUpdate 보다 먼저(§12-27 ⓒ).
    let rn = gchange(&h, "carol@local", &gid, "rename", &[], Some("새 팀"));
    let rn_id = rn["msg_id"].as_str().unwrap().to_owned();
    carol
        .enqueue(&Outgoing::GroupChange { message: rn })
        .unwrap();
    let fin = wait(&mut crx, "carol rename 확정", |i| {
        matches!(
            i,
            Inbound::GroupChangePending { .. } | Inbound::GroupUpdate { .. }
        )
    })
    .await;
    assert!(
        matches!(&fin, Inbound::GroupChangePending { change_id, pending: lodelai_relay_client::ChangePending::Final, seq: Some(_) } if *change_id == rn_id),
        "{fin:?}"
    );
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        let (_, st) = update_of(rx, who, "rename").await;
        assert_eq!(st.name, "새 팀", "{who}");
    }
}

/// 묶음 22 h2·§12-13 ②: 조직에서 빠진 사람(디렉터리에서 사라짐)은 relay duty remove_user 로 남은 기기가 org_left Commit 을 내
/// 잎을 모두 뺀다 — 남은 멤버 모두 GroupUpdate org_left, 그 뒤 글은 빠진 사람에게 가지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 조직에서_빠진_사람은_org_left_로_빠진다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    relay_sql(
        &h,
        "INSERT INTO org_admins(org_id, user) SELECT org, user FROM users WHERE user = 'alice'",
    );
    {
        let _order = h.app.group_order.lock().unwrap();
        h.app
            .db
            .member_remove("alice", "carol", h.fx.clock.now().0)
            .unwrap();
        lodelai_relay::ws::announce_org_removal(&h.app, "alice");
    }
    settle(&h).await;
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx)] {
        let u = wait(
            rx,
            &format!("{who} org_left"),
            |i| matches!(i, Inbound::GroupUpdate { op, .. } if op == "org_left"),
        )
        .await;
        let Inbound::GroupUpdate { subject, state, .. } = u else {
            unreachable!()
        };
        assert_eq!(subject.as_deref(), Some("carol@local"), "{who}");
        let mut mm = state.members.clone();
        mm.sort();
        assert_eq!(mm, ["alice@local", "bob@local"], "{who}");
    }
    assert_eq!(alice.group_send_check(&gid).unwrap(), 1, "잎은 bob 하나");
}

/// §12-25: 관리자 alice 가 혼자 나가면 유효 관리자 = 가장 작은 잎(bob — create 의 첫 subject)의 사용자. bob 의 remove 는 확정되고,
/// carol 의 remove 는 relay 가 unroutable 로 거절한다.
#[tokio::test(flavor = "multi_thread")]
async fn 관리자가_나가면_가장_작은_잎이_관리자() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let dk = h.user("dave", 4).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    ready(&mut drx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local", "dave@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [
        ("alice", &mut arx),
        ("bob", &mut brx),
        ("carol", &mut crx),
        ("dave", &mut drx),
    ] {
        update_of(rx, who, "create").await;
    }
    let tick = ticker(&h);
    let mut lv = gchange(&h, "alice@local", &gid, "leave", &[], None);
    lv["body"] = json!({"enc": "plain", "text": json!({"op": "leave"}).to_string()});
    alice
        .enqueue(&Outgoing::GroupChange { message: lv })
        .unwrap();
    // leave(app) 땐 나간 사람만 빠지고, 잎을 빼는 Commit 확정 때 줄 없는 update 로 승계가 보인다(§12-25 ⓐ). duty 를 받아
    // leave Commit 을 낸 기기도(relay 가 셋 중 아무나 고름 — #499 는 그 기기가 제 그룹을 지웠다) 같은 줄을 본다.
    for (who, rx) in [("bob", &mut brx), ("carol", &mut crx), ("dave", &mut drx)] {
        let (_, st) = update_of(rx, who, "leave").await;
        assert!(st.admins.is_empty(), "{who} {:?}", st.admins);
        let (_, st) = update_of(rx, who, "update").await;
        assert_eq!(st.admins, ["bob@local"], "{who}");
    }
    // alice 잎을 빼는 leave Commit(duty)이 확정될 때까지 — 그 전엔 alice 잎이 남아 유효 관리자가 아직 alice 다(§12-25).
    let mut gone = false;
    for _ in 0..150 {
        if bob.group_send_check(&gid).unwrap_or(0) == 2
            && carol.group_send_check(&gid).unwrap_or(0) == 2
        {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(gone, "alice 잎이 빠지지 않음");
    // carol 은 관리자가 아니다 — relay 가 거절.
    let mut rm = gchange(&h, "carol@local", &gid, "remove", &[], None);
    rm["subject"] = json!("dave@local");
    let cid = rm["msg_id"].as_str().unwrap().to_owned();
    carol
        .enqueue(&Outgoing::GroupChange { message: rm })
        .unwrap();
    let n = wait(
        &mut crx,
        "carol nack",
        |i| matches!(i, Inbound::Nack { msg_id, .. } if *msg_id == cid),
    )
    .await;
    let Inbound::Nack { reason, .. } = n else {
        unreachable!()
    };
    assert_eq!(reason, "unroutable");
    // bob(유효 관리자)의 remove 는 확정된다.
    let mut rm = gchange(&h, "bob@local", &gid, "remove", &[], None);
    rm["subject"] = json!("dave@local");
    bob.enqueue(&Outgoing::GroupChange { message: rm }).unwrap();
    for (who, rx) in [("bob", &mut brx), ("carol", &mut crx)] {
        let (_, st) = update_of(rx, who, "remove").await;
        let mut mm = st.members.clone();
        mm.sort();
        assert_eq!(mm, ["bob@local", "carol@local"], "{who}");
    }
    tick.abort();
}

/// QA 묶음 16 §3a ④ 의 MLS 판: 끊긴 동안 관리자 alice 가 조직에서 빠지면 남은 기기가 org_left Commit 을 내고(꺼진 멤버가 붙어
/// ack 하면 확정), 승계 관리자(§12-25 가장 작은 잎)가 이름을 바꾼다 — 다시 붙은 bob 과 계속 켜 둔 carol 의 상태가 같다.
async fn org_left_reconnect_converges(successor_offline: bool) {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    // 처음 subject 순서 = 잎 순서 — 승계자는 앞사람.
    let order: [&str; 2] = if successor_offline {
        ["bob@local", "carol@local"]
    } else {
        ["carol@local", "bob@local"]
    };
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(&h, "alice@local", &gid, "create", &order, Some("팀")),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    for (who, rx) in [("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "rename").await;
    }
    drop(alice);
    drop(arx);
    // bob 끊김.
    drop(bob);
    drop(brx);
    relay_sql(
        &h,
        "INSERT INTO org_admins(org_id, user) SELECT org, user FROM users WHERE user = 'carol'",
    );
    {
        let _order = h.app.group_order.lock().unwrap();
        h.app
            .db
            .member_remove("carol", "alice", h.fx.clock.now().0)
            .unwrap();
        lodelai_relay::ws::announce_org_removal(&h.app, "carol");
    }
    let successor = order[0];
    if !successor_offline {
        // carol 이 승계자 — 꺼진 bob 이 ack 하기 전이라 org_left 는 아직 확정 전이지만 이름은 바꿀 수 있다.
        carol
            .enqueue(&Outgoing::GroupChange {
                message: gchange(&h, "carol@local", &gid, "rename", &[], Some("새 이름")),
            })
            .unwrap();
        update_of(&mut crx, "carol", "rename").await;
    }
    // 다시 붙는다(같은 DB·같은 키).
    let (bob2, mut brx2) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx2).await;
    settle(&h).await;
    for (who, rx) in [("bob", &mut brx2), ("carol", &mut crx)] {
        let (_, st) = update_of(rx, who, "org_left").await;
        assert_eq!(st.admins, [successor], "{who} 승계는 가장 작은 잎");
    }
    if successor_offline {
        bob2.enqueue(&Outgoing::GroupChange {
            message: gchange(&h, "bob@local", &gid, "rename", &[], Some("새 이름")),
        })
        .unwrap();
        update_of(&mut crx, "carol", "rename").await;
    }
    let mut same = false;
    for _ in 0..100 {
        let (b, c) = (
            bob2.group(&gid).unwrap().unwrap(),
            carol.group(&gid).unwrap().unwrap(),
        );
        if (b.name.as_str(), &b.members, &b.admins) == ("새 이름", &c.members, &c.admins)
            && c.name == "새 이름"
        {
            same = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(same, "다시 붙은 bob 과 carol 의 그룹 상태가 같아야");
}

#[tokio::test(flavor = "multi_thread")]
async fn qa_org_left_reconnect_converges_successor_online() {
    org_left_reconnect_converges(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn qa_org_left_reconnect_converges_successor_offline() {
    org_left_reconnect_converges(true).await;
}

/// #605: 처음 멤버 한 사람의 KeyPackage 가 아직 없으면(그 사람이 아직 접속하지 않음) 다른 사람 몫만으로 create Commit 을 봉인하지
/// 않고 물러섰다가, 그 사람이 올린 뒤 모두 넣어 만든다(전엔 relay invalid_commit 두 번 → 만들기 실패 internal).
#[tokio::test(flavor = "multi_thread")]
async fn 처음_멤버_keypackage_가_늦어도_만들기는_기다렸다_된다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    // carol 이 KeyPackage 를 올리기 전 — 실패도 확정도 없어야 한다.
    let until = tokio::time::Instant::now() + Duration::from_millis(1500);
    while let Ok(Some(i)) = tokio::time::timeout_at(until, arx.recv()).await {
        assert!(
            !matches!(i, Inbound::Nack { .. } | Inbound::GroupUpdate { .. }),
            "carol KeyPackage 전에 끝남: {i:?}"
        );
    }
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut crx).await;
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
}

/// #605 리뷰: 넣을 사람 중 디렉터리 기기가 없는 사람(가입 전·조직에서 빠짐)이 있으면 두 번(약 6초) 기다린 뒤 unroutable 로
/// 실패가 보인다(전엔 다른 사람 몫만으로 봉인 → invalid 두 번 → internal, 고친 첫 판은 끝없이 물러섬).
#[tokio::test(flavor = "multi_thread")]
async fn 기기_없는_사람을_넣는_만들기는_곧_실패로_보인다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let change = gchange(
        &h,
        "alice@local",
        &gid,
        "create",
        &["bob@local", "nobody@local"],
        Some("팀"),
    );
    let want = change["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: change })
        .unwrap();
    let n = wait(&mut arx, "만들기 실패", |i| {
        matches!(i, Inbound::Nack { .. })
    })
    .await;
    let Inbound::Nack {
        msg_id,
        reason,
        until: None,
    } = n
    else {
        unreachable!()
    };
    assert_eq!(
        (msg_id.as_str(), reason.as_str()),
        (want.as_str(), "unroutable")
    );
}

/// 그룹을 켠 relay(연결 헤더)에서 group start 가 unroutable(그 gid 를 남이 이미 씀 — Conflict)이면 그 만들기
/// 행만 실패로 끝내고 그룹 꺼짐(groups_off)으로 보지 않는다 — 다른 그룹 글은 그대로 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 그룹_시작이_겹치면_그_방만_실패하고_다른_그룹은_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let dk = h.user("dave", 4).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    for rx in [&mut arx, &mut brx, &mut crx, &mut drx] {
        ready(rx).await;
    }
    // bob 이 gid X 를 먼저 만든다(alice 는 멤버 아님).
    let x = h.fx.ids.next_ulid().to_lowercase();
    bob.enqueue(&Outgoing::GroupChange {
        message: gchange(
            &h,
            "bob@local",
            &x,
            "create",
            &["carol@local", "dave@local"],
            Some("X"),
        ),
    })
    .unwrap();
    wait(
        &mut crx,
        "carol X GroupUpdate",
        |i| matches!(i, Inbound::GroupUpdate { gid, .. } if *gid == x),
    )
    .await;
    // alice 의 그룹 Y.
    let y = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &y,
                "create",
                &["bob@local", "carol@local"],
                Some("Y"),
            ),
        })
        .unwrap();
    wait(
        &mut brx,
        "bob Y GroupUpdate",
        |i| matches!(i, Inbound::GroupUpdate { gid, .. } if *gid == y),
    )
    .await;
    // alice 가 같은 gid X 로 만들기 → relay start Conflict → 그 행만 unroutable, 그룹 꺼짐 아님.
    let m = gchange(
        &h,
        "alice@local",
        &x,
        "create",
        &["bob@local", "carol@local"],
        Some("X2"),
    );
    let dup = m["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: m })
        .unwrap();
    let got = wait(&mut arx, "겹친 만들기 Nack·GroupsOff", |i| {
        matches!(i, Inbound::GroupsOff)
            || matches!(i, Inbound::Nack { msg_id, .. } if *msg_id == dup)
    })
    .await;
    let Inbound::Nack { reason, .. } = got else {
        panic!("그룹 꺼짐으로 봄: {got:?}")
    };
    assert_eq!(reason, "unroutable");
    // 다른 그룹 Y 글은 그대로 간다.
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{y}@{SERVER}"), "Y 글"),
        })
        .expect("그룹 꺼짐 아님");
    assert_eq!(got_text(&mut brx).await, "Y 글");
}

/// 묶음 16 §3b 의 MLS 판: 그룹 끔이면 그룹 주소·kind group 은 큐에 넣기 전에 막고, 켠 bob 이 alice 를 넣은 그룹의 Welcome·글은
/// core 에 넘기지 않고 버린다(relay 가 그룹을 켜 두었어도 — 반신뢰). 보통 1:1 chat 은 간다.
#[tokio::test(flavor = "multi_thread")]
async fn groups_off_blocks_sending_and_drops_received_group_messages() {
    use lodelai_relay_client::Error;
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start_groups("alice", &ak, 1, "a.db", false);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let gaddr = format!("+{gid}@{SERVER}");
    for out in [
        Outgoing::Send {
            message: h.chat("alice@local", &gaddr, "x"),
        },
        Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        },
    ] {
        assert!(
            matches!(alice.enqueue(&out), Err(Error::GroupsOff)),
            "{out:?}"
        );
    }
    bob.enqueue(&Outgoing::GroupChange {
        message: gchange(
            &h,
            "bob@local",
            &gid,
            "create",
            &["alice@local"],
            Some("팀"),
        ),
    })
    .unwrap();
    update_of(&mut brx, "bob", "create").await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &gaddr, "그룹 글"),
    })
    .unwrap();
    let plain = h.chat("bob@local", "alice@local", "보통");
    bob.enqueue(&Outgoing::Send {
        message: plain.clone(),
    })
    .unwrap();
    loop {
        let i = tokio::time::timeout(Duration::from_secs(60), arx.recv())
            .await
            .expect("보통 chat 대기")
            .expect("수신 끝");
        match i {
            Inbound::GroupUpdate { .. } | Inbound::GroupStale { .. } => {
                panic!("그룹 꺼짐인데 그룹 상태가 왔다: {i:?}")
            }
            Inbound::Deliver { message, ack } => {
                ack.ack();
                assert_eq!(
                    message["msg_id"], plain["msg_id"],
                    "그룹 글이 넘어왔다: {message}"
                );
                break;
            }
            _ => {}
        }
    }
    assert!(alice.group(&gid).unwrap().is_none(), "그룹 상태가 없다");
}

/// h1 리뷰·§12-21: 다른 멤버가 모두 꺼져 내 add Commit 이 1시간 뒤 무효가 되면, 보낸 기기가 같은 add 를 다음 epoch 로 다시 낸다 —
/// 꺼졌던 bob 이 붙어 ack 하면 확정되고 dave 가 들어온다.
#[tokio::test(flavor = "multi_thread")]
async fn 무효가_된_add_는_다시_나가_확정된다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut drx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx)] {
        update_of(rx, who, "create").await;
    }
    update_of(&mut brx, "bob", "rename").await;
    // bob 을 막힘으로 다시 켜 add 에 fail 을 내게 한다(연결된 투표자가 없으면 배달 직후 확정이라 — #846).
    bob.shutdown().await;
    drop(brx);
    stall(&h, "b.db", 2, &gid, true);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    let mut add = gchange(&h, "alice@local", &gid, "add", &[], None);
    add["subject"] = json!("dave@local");
    add["body"] =
        json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    until_fail(&h, &gid, "bob").await;
    // 풀린 bob 으로 다시 켠 뒤 창 끝 — 연결된 투표자(bob) 전원 fail 이라 무효(§7-28), 다시 낸 add 는 bob 이 ack.
    bob.shutdown().await;
    drop(brx);
    stall(&h, "b.db", 2, &gid, false);
    let (_bob2, mut brx2) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx2).await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let tick = ticker(&h);
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx2), ("dave", &mut drx)] {
        let (_, st) = update_of(rx, who, "add").await;
        assert_eq!(st.members.len(), 3, "{who}");
    }
    tick.abort();
}

/// §12-27 ⓒ d4c07549: 무효가 된 remove 도 다시 낸다(전엔 create·add 만) — 보낸 기기의 줄은 waiting → retry → (다시 봉인)
/// waiting → final{seq}(GroupUpdate 보다 먼저), 키는 처음 msg_id 그대로.
#[tokio::test(flavor = "multi_thread")]
async fn 무효가_된_remove_도_다시_나가_확정된다() {
    use lodelai_relay_client::ChangePending as P;
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut crx, "carol", "rename").await;
    drop((carol, crx));
    // bob 을 막힘으로 다시 켜 remove 에 fail 을 내게 한다(#846 — 연결된 투표자가 없으면 배달 직후 확정).
    bob.shutdown().await;
    drop(brx);
    stall(&h, "b.db", 2, &gid, true);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    let mut rm = gchange(&h, "alice@local", &gid, "remove", &[], None);
    rm["subject"] = json!("carol@local");
    rm["body"] = json!({"enc": "plain", "text": json!({"op": "remove", "subject": "carol@local"}).to_string()});
    let rm_id = rm["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: rm })
        .unwrap();
    wait(
        &mut arx,
        "remove ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == rm_id),
    )
    .await;
    until_fail(&h, &gid, "bob").await;
    bob.shutdown().await;
    drop(brx);
    stall(&h, "b.db", 2, &gid, false);
    let (_bob2, mut brx2) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx2).await;
    h.fx.clock.advance(61_000);
    h.app.expire_tick();
    let tick = ticker(&h);
    let mut seen = Vec::new();
    loop {
        let i = wait(&mut arx, "remove 기다림·확정", |i| {
            matches!(
                i,
                Inbound::GroupChangePending { .. } | Inbound::GroupUpdate { .. }
            )
        })
        .await;
        match i {
            Inbound::GroupChangePending {
                change_id,
                pending,
                seq,
            } => {
                assert_eq!(change_id, rm_id);
                let fin = pending == P::Final;
                seen.push((pending, seq.is_some()));
                if fin {
                    break;
                }
            }
            Inbound::GroupUpdate { op, .. } => assert_ne!(op, "remove", "확정 줄은 Final 뒤"),
            _ => unreachable!(),
        }
    }
    // 처음 봉인의 waiting 은 위 ack 기다림이 지나갔다.
    assert_eq!(
        seen,
        vec![(P::Retry, false), (P::Waiting, false), (P::Final, true)]
    );
    let (_, st) = update_of(&mut arx, "alice", "remove").await;
    assert!(!st.members.iter().any(|x| x == "carol@local"));
    tick.abort();
}

/// §12-26 ⑤: 같은 add 가 3번 무효면 멈추고 처음 행을 실패(Nack commit_void)로 — 더 다시 내지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 같은_변경이_세_번_무효면_멈춘다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut drx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "rename").await;
    // 막힌 bob 을 붙은 채 둔다 — Commit 마다 fail 이라 창 끝마다 무효(§7-28; 꺼 두면 #846 으로 배달 직후 확정).
    bob.shutdown().await;
    drop(brx);
    stall(&h, "b.db", 2, &gid, true);
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    let mut add = gchange(&h, "alice@local", &gid, "add", &[], None);
    add["subject"] = json!("dave@local");
    add["body"] =
        json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    // 다시 낸 add 가 relay 에 닿고 bob 의 fail 이 올 틈을 두고 창을 네 번 넘긴다.
    for _ in 0..4 {
        tokio::time::sleep(Duration::from_millis(700)).await;
        h.fx.clock.advance(61_000);
        h.app.expire_tick();
    }
    let n = wait(
        &mut arx,
        "add 실패",
        |i| matches!(i, Inbound::Nack { msg_id, .. } if *msg_id == add_id),
    )
    .await;
    let Inbound::Nack { reason, .. } = n else {
        unreachable!()
    };
    assert_eq!(reason, "commit_void");
    assert_eq!(
        alice.group_send_check(&gid).unwrap(),
        1,
        "잎은 그대로 alice·bob"
    );
}

/// 묶음 22 h3: 내 add 가 확정을 기다리는 동안 ⓐ 앱을 다시 켜도 쥔 Commit 이 남아 확정 때 merge 되고, ⓑ 그동안 보낸 글은 epoch N
/// 으로 나가 바로 열리며, ⓒ 남(bob)의 Commit 은 relay 의 stale_epoch 에 물러섰다가 확정 뒤 다음 epoch 로 나가 확정된다.
#[tokio::test(flavor = "multi_thread")]
async fn 확정_전_재시작과_겹친_commit() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let dk = h.user("dave", 4).await;
    let ek = h.user("erin", 5).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    let (erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    for rx in [&mut arx, &mut brx, &mut crx, &mut drx, &mut erx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "erin@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("erin", &mut erx)] {
        update_of(rx, who, "create").await;
    }
    // ack 하지 않는 멤버(erin)를 붙은 채 둔다 — 연결된 투표자가 다 ack 하면 창 없이 확정되므로(#599·hosted 11-04 A) 확정 전
    // 장면이 남게. 그 그룹을 막힘으로 두면 Commit 마다 commit_fail 만 낸다. 창은 ticker 를 돌릴 때만 끝난다.
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut erx, "erin", "rename").await;
    erin.shutdown().await;
    drop(erx);
    MlsStore::open(&h.dir.path().join("e.db"), &store_key(5), Arc::new(OsRng))
        .unwrap()
        .set_state(
            gid.as_bytes(),
            lodelai_relay_client::mls_store::GroupState::StalledServer,
            "test",
            1,
        )
        .unwrap();
    let (_erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    wait(&mut erx, "erin ready", |i| {
        matches!(i, Inbound::Ready { .. })
    })
    .await;
    let add_of = |from: &str, who: &str| {
        let mut m = gchange(&h, from, &gid, "add", &[], None);
        m["subject"] = json!(who);
        m["body"] =
            json!({"enc": "plain", "text": json!({"op": "add", "subject": who}).to_string()});
        m
    };
    let add = add_of("alice@local", "dave@local");
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    // ⓒ alice 의 add 가 relay 에 확정 전으로 있는 동안 bob 이 carol 을 넣는다 — stale_epoch.
    bob.enqueue(&Outgoing::GroupChange {
        message: add_of("bob@local", "carol@local"),
    })
    .unwrap();
    // ⓐ 확정 전에 alice 를 다시 켠다(같은 DB).
    drop(alice);
    drop(arx);
    let (alice2, mut arx2) = h.start("alice", &ak, 1, "a.db");
    ready(&mut arx2).await;
    // ⓑ 확정 전에 보낸 글은 epoch N 으로 — bob 이 곧바로 연다.
    alice2
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "확정 전"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "확정 전");
    let tick = ticker(&h);
    for (who, rx) in [("bob", &mut brx), ("dave", &mut drx), ("alice", &mut arx2)] {
        let (_, st) = update_of(rx, who, "add").await;
        assert_eq!(st.members.len(), 4, "{who} dave 들어옴");
    }
    for (who, rx) in [("alice", &mut arx2), ("bob", &mut brx), ("carol", &mut crx)] {
        let st = loop {
            let (_, st) = update_of(rx, who, "add").await;
            if st.members.len() == 5 {
                break st;
            }
        };
        assert!(st.members.iter().any(|m| m.starts_with("carol")), "{who}");
    }
    tick.abort();
}

/// hosted 11-04 C(대상별 차례): bob 의 그룹 add 가 relay 의 확정 전 Commit 때문에 `stale_epoch` 로 물러서 있는 동안,
/// ⓐ 다른 대상(alice 1:1)에게 보낸 사진·글은 그 뒤에 막히지 않고 간다(첨부 예약까지). ⓑ 같은 그룹에 보낸 글은 add 뒤에 남는다
/// (같은 대상 안의 순서). 확정되면(ticker) 그룹 쪽도 다 나간다.
#[tokio::test(flavor = "multi_thread")]
async fn 그룹_commit_이_물러선_동안_다른_대상에게는_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let dk = h.user("dave", 4).await;
    let ek = h.user("erin", 5).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    let (erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    for rx in [&mut arx, &mut brx, &mut crx, &mut drx, &mut erx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "erin@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("erin", &mut erx)] {
        update_of(rx, who, "create").await;
    }
    // ack 하지 않는 멤버(erin)를 붙은 채 둔다 — 연결된 투표자가 다 ack 하면 창 없이 확정되므로(#599·hosted 11-04 A) 확정 전
    // 장면이 남게. 그 그룹을 막힘으로 두면 Commit 마다 commit_fail 만 낸다. 창은 ticker 를 돌릴 때만 끝난다.
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut erx, "erin", "rename").await;
    erin.shutdown().await;
    drop(erx);
    MlsStore::open(&h.dir.path().join("e.db"), &store_key(5), Arc::new(OsRng))
        .unwrap()
        .set_state(
            gid.as_bytes(),
            lodelai_relay_client::mls_store::GroupState::StalledServer,
            "test",
            1,
        )
        .unwrap();
    let (_erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    wait(&mut erx, "erin ready", |i| {
        matches!(i, Inbound::Ready { .. })
    })
    .await;
    let add_of = |from: &str, who: &str| {
        let mut m = gchange(&h, from, &gid, "add", &[], None);
        m["subject"] = json!(who);
        m["body"] =
            json!({"enc": "plain", "text": json!({"op": "add", "subject": who}).to_string()});
        m
    };
    let add = add_of("alice@local", "dave@local");
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    // bob 의 add(carol) — alice 의 확정 전 add 때문에 stale_epoch 로 물러선다. 그 뒤에 같은 그룹 글·alice 에게 사진과 글.
    bob.enqueue(&Outgoing::GroupChange {
        message: add_of("bob@local", "carol@local"),
    })
    .unwrap();
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "그룹 글"),
    })
    .unwrap();
    let photo = h.dir.path().join("photo.png");
    std::fs::write(&photo, b"\x89PNG fake").unwrap();
    bob.enqueue(&Outgoing::SendFiles {
        message: h.chat("bob@local", "alice@local", "사진"),
        attachments: vec![lodelai_relay_client::OutFile {
            path: photo,
            name: "photo.png".into(),
            mime: "image/png".into(),
            role: None,
            sha256: None,
            size_px: None,
        }],
    })
    .unwrap();
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "1:1 글"),
    })
    .unwrap();
    // ⓐ 확정 전인데도 alice 는 사진·글을 받는다(예전엔 맨 앞의 물러선 add 뒤에서 relay 에 예약조차 못 갔다).
    assert_eq!(got_text(&mut arx).await, "사진");
    assert_eq!(got_text(&mut arx).await, "1:1 글");
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        1,
        "아직 확정 전"
    );
    // 보낸 쪽은 그룹 행이 왜 기다리는지 안다(보낸 쪽 '기다리는 중' 표시) — 다른 대상(alice 1:1)은 없다.
    let waits = bob.send_waits();
    assert!(
        waits.iter().any(|w| w.to == format!("+{gid}")
            && w.reason == lodelai_relay_client::SendWaitReason::GroupChange),
        "{waits:?}"
    );
    assert!(waits.iter().all(|w| w.to != "alice"), "{waits:?}");
    // ⓑ 같은 그룹 글은 add 뒤 — 확정 전엔 dave·carol 어디에도 안 갔다(alice 쪽에도 그룹 글은 아직 없다).
    let early = tokio::time::timeout(Duration::from_secs(3), got_text(&mut arx)).await;
    assert!(early.is_err(), "그룹 글이 add 보다 먼저 나감: {early:?}");
    let tick = ticker(&h);
    assert_eq!(got_text(&mut arx).await, "그룹 글");
    tick.abort();
}

/// g025 11-04: 두 멤버가 같은 사람을 거의 같이 더하면 먼저 간 add 만 확정되고, 늦은 쪽(bob)의 add 는 `stale_epoch` 로
/// 물러선다. 확정 뒤 bob 의 add 는 이미 멤버라 Commit 을 만들 수 없다 — 예전엔 60초마다 다시 하며 같은 그룹 행(그 뒤 그룹
/// 글)을 끝없이 막았다. 이제 그 add 행을 확정으로 끝내고(줄 기다림만 지움), 뒤의 그룹 글이 간다.
/// Crew2 꼴: bob 의 (bob, dave 기기) KeyPackage 가져오기가 하루 상한에 닿아 있으면 bob 의 add 는 확정 **전에** `rate_limited`
/// 로 600초 물러선다 — 확정(epoch 움직임)이 그 물러섬도 풀어야 '이미 멤버' 판정까지 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 이미_멤버인_사람을_더하는_add_는_끝내고_뒤_그룹_글이_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let ek = h.user("erin", 5).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    let (erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    for rx in [&mut arx, &mut brx, &mut drx, &mut erx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "erin@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("erin", &mut erx)] {
        update_of(rx, who, "create").await;
    }
    // 확정 전 장면을 남기려고 erin 을 붙은 채 막힘으로(ack 하지 않음) — 창은 ticker 를 돌릴 때만 끝난다.
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut erx, "erin", "rename").await;
    erin.shutdown().await;
    drop(erx);
    MlsStore::open(&h.dir.path().join("e.db"), &store_key(5), Arc::new(OsRng))
        .unwrap()
        .set_state(
            gid.as_bytes(),
            lodelai_relay_client::mls_store::GroupState::StalledServer,
            "test",
            1,
        )
        .unwrap();
    let (_erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    wait(&mut erx, "erin ready", |i| {
        matches!(i, Inbound::Ready { .. })
    })
    .await;
    let add_of = |from: &str, who: &str| {
        let mut m = gchange(&h, from, &gid, "add", &[], None);
        m["subject"] = json!(who);
        m["body"] =
            json!({"enc": "plain", "text": json!({"op": "add", "subject": who}).to_string()});
        m
    };
    let add = add_of("alice@local", "dave@local");
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    // bob 의 (bob → dave 기기) 하루 claim 을 다 쓴 것으로(KP_CLAIM_PAIR_PER_DAY) — 5분 뒤 풀리게(10분 안 = 기다림 길).
    let now = h.fx.clock.now().0 - 24 * 60 * 60 * 1000 + 5 * 60 * 1000;
    let dave_dev = dk.device_id().as_str().to_owned();
    relay_sql(
        &h,
        &(0..25)
            .map(|_| {
                format!("INSERT INTO mls_kp_claims(claimer, target, owner, at_ms) VALUES ('bob', '{dave_dev}', 0, {now});")
            })
            .collect::<String>(),
    );
    // bob 도 dave 를 더한다 — alice 의 add 가 확정 전이라 bob 쪽엔 dave 가 아직 없다 → claim → rate_limited 로 물러선다.
    // 그 뒤 같은 그룹에 글.
    let late = add_of("bob@local", "dave@local");
    let late_id = late["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::GroupChange { message: late })
        .unwrap();
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "그룹 글"),
    })
    .unwrap();
    // 0.2.5 다시 보기: 내 가져오기 상한 물러섬은 그룹 변경이 아니라 rate_limited(다시 될 시각 동반)로 보인다.
    let mut limited = None;
    for _ in 0..100 {
        limited = bob.send_waits().into_iter().find(|w| {
            w.to == format!("+{gid}")
                && w.reason == lodelai_relay_client::SendWaitReason::RateLimited
        });
        if limited.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let limited = limited.expect("상한 기다림");
    assert!(limited.until.is_some(), "다시 될 시각: {limited:?}");
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        1,
        "아직 확정 전"
    );
    tokio::time::sleep(Duration::from_secs(1)).await;
    let tick = ticker(&h);
    // bob 의 add 줄은 실패가 아니라 확정(seq 없음 — 기다림만 지움)으로 끝난다.
    wait(&mut brx, "bob add 끝남", |i| {
        matches!(i, Inbound::GroupChangePending {
            change_id,
            pending: lodelai_relay_client::ChangePending::Final,
            seq: None,
        } if *change_id == late_id)
    })
    .await;
    assert_eq!(got_text(&mut drx).await, "그룹 글");
    assert_eq!(got_text(&mut arx).await, "그룹 글");
    tick.abort();
}

/// g025 11-04 판정 ②: KeyPackage 가져오기 상한이 10분보다 오래 남았으면(`until`) 사람이 낸 add 는 기다리지 않고 바로
/// 실패(Nack rate_limited, 그 변경 줄 키) — 코어가 실패 줄·다시 하기를 그린다. 뒤의 같은 그룹 글은 막히지 않고 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 가져오기_상한이_길면_add_는_바로_실패하고_뒤_글은_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let (_alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    for rx in [&mut arx, &mut brx, &mut drx] {
        ready(rx).await;
    }
    let tick = ticker(&h);
    let gid = h.fx.ids.next_ulid().to_lowercase();
    bob.enqueue(&Outgoing::GroupChange {
        message: gchange(
            &h,
            "bob@local",
            &gid,
            "create",
            &["alice@local"],
            Some("팀"),
        ),
    })
    .unwrap();
    update_of(&mut arx, "alice", "create").await;
    let now = h.fx.clock.now().0;
    let dave_dev = dk.device_id().as_str().to_owned();
    relay_sql(
        &h,
        &(0..25)
            .map(|_| {
                format!("INSERT INTO mls_kp_claims(claimer, target, owner, at_ms) VALUES ('bob', '{dave_dev}', 0, {now});")
            })
            .collect::<String>(),
    );
    let mut add = gchange(&h, "bob@local", &gid, "add", &[], None);
    add["subject"] = json!("dave@local");
    add["body"] =
        json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "상한 뒤 글"),
    })
    .unwrap();
    wait(&mut brx, "add 실패", |i| {
        matches!(i, Inbound::Nack { msg_id, reason, until: Some(_) } if *msg_id == add_id && reason == "rate_limited")
    })
    .await;
    while got_text(&mut arx).await != "상한 뒤 글" {}
    tick.abort();
}

/// g025c: 만들 때 넣은 사람의 KeyPackage 가져오기가 짧은 상한(10분 안)에 걸리면 만들기 행이 물러서 로컬 그룹이 아직 없다.
/// 그동안 그 그룹에 보내기를 말없이 거절(NotGroupMember)하지 않고 받아 만들기 행 뒤에 세우고, 기다림 까닭은 rate_limited +
/// 다시 될 시각이다.
#[tokio::test(flavor = "multi_thread")]
async fn 만드는_중_상한이면_그룹_글은_줄_서고_상한_기다림() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    for rx in [&mut arx, &mut brx, &mut crx] {
        ready(rx).await;
    }
    // alice 의 (alice → carol 기기) 하루 claim 을 다 쓴 것으로 — 몇 초 뒤 풀리게(10분 안 = 기다림 길, 물러섬은 최소 2초).
    let now = h.fx.clock.now().0 - 24 * 60 * 60 * 1000 + 3 * 1000;
    let carol_dev = ck.device_id().as_str().to_owned();
    relay_sql(
        &h,
        &(0..25)
            .map(|_| {
                format!("INSERT INTO mls_kp_claims(claimer, target, owner, at_ms) VALUES ('alice', '{carol_dev}', 0, {now});")
            })
            .collect::<String>(),
    );
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    // 만들기가 물러선 동안(로컬 그룹 없음) 보내기는 받는다.
    let mut ok = false;
    for _ in 0..100 {
        if alice.send_waits().iter().any(|w| w.to == format!("+{gid}")) {
            ok = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(ok, "만들기 행이 물러섬");
    assert!(alice.group(&gid).unwrap().is_none(), "아직 로컬 그룹 없음");
    assert_eq!(
        alice.group_send_check(&gid).unwrap(),
        0,
        "거절하지 않고 줄 섬"
    );
    let chat = h.chat("alice@local", &format!("+{gid}@{SERVER}"), "만드는 중 글");
    let chat_id = chat["msg_id"].as_str().unwrap().to_owned();
    alice.enqueue(&Outgoing::Send { message: chat }).unwrap();
    let mut waits = Vec::new();
    for _ in 0..100 {
        waits = alice.send_waits();
        if waits.iter().any(|w| w.msg_id == chat_id) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let w = waits
        .iter()
        .find(|w| w.msg_id == chat_id)
        .expect("글도 기다림으로 보임");
    assert_eq!(w.reason, lodelai_relay_client::SendWaitReason::RateLimited);
    assert!(w.until.is_some(), "다시 될 시각: {w:?}");
    // 다시 해 볼 때 상한이 길어져 있으면 만들기가 실패로 끝나고, 뒤에 선 글도 조용히 남지 않고 보내기 실패로 끝난다.
    let fresh = h.fx.clock.now().0;
    relay_sql(
        &h,
        &(0..25)
            .map(|_| {
                format!("INSERT INTO mls_kp_claims(claimer, target, owner, at_ms) VALUES ('alice', '{carol_dev}', 0, {fresh});")
            })
            .collect::<String>(),
    );
    wait(
        &mut arx,
        "뒤 글 실패",
        |i| matches!(i, Inbound::Nack { msg_id, .. } if *msg_id == chat_id),
    )
    .await;
}

/// g025 11-04 Crew5: 다시 들어야 하는 기기(bob)가 켜졌는데 그룹에 확정 전 Commit 이 있으면 external commit 이 `stale_epoch`
/// 로 물러나 로컬 그룹이 없다. 그동안 그 그룹에 보내기를 조용히 거절(NotGroupMember)하지 않고 받아 다시 들기 뒤에 세운다
/// (까닭 GroupRejoin). 확정 뒤 다시 들고 글이 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 다시_드는_중_그룹에_보낸_글은_기다렸다_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let ek = h.user("erin", 5).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    let (erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    for rx in [&mut arx, &mut brx, &mut drx, &mut erx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "erin@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("erin", &mut erx)] {
        update_of(rx, who, "create").await;
    }
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut erx, "erin", "rename").await;
    erin.shutdown().await;
    drop(erx);
    MlsStore::open(&h.dir.path().join("e.db"), &store_key(5), Arc::new(OsRng))
        .unwrap()
        .set_state(
            gid.as_bytes(),
            lodelai_relay_client::mls_store::GroupState::StalledServer,
            "test",
            1,
        )
        .unwrap();
    let (_erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    wait(&mut erx, "erin ready", |i| {
        matches!(i, Inbound::Ready { .. })
    })
    .await;
    // bob 을 내리고 다시 들기 표시 — 그 사이 alice 의 dave 더하기가 확정 전으로 남는다.
    bob.shutdown().await;
    drop(brx);
    let mut add = gchange(&h, "alice@local", &gid, "add", &[], None);
    add["subject"] = json!("dave@local");
    add["body"] =
        json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) VALUES ('{}', '{gid}', 0)",
            bk.device_id().as_str()
        ),
    );
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    // external commit 이 물러나 로컬 그룹이 없는 때까지.
    for _ in 0..100 {
        if bob.group(&gid).unwrap().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(bob.group(&gid).unwrap().is_none(), "다시 드는 중이 아님");
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        1,
        "아직 확정 전"
    );
    assert!(
        bob.group_send_check(&gid).is_ok(),
        "다시 드는 중 보내기 거절"
    );
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "다시 드는 중 글"),
    })
    .unwrap();
    for _ in 0..50 {
        if !bob.send_waits().is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let waits = bob.send_waits();
    assert!(
        waits.iter().any(|w| w.to == format!("+{gid}")
            && w.reason == lodelai_relay_client::SendWaitReason::GroupRejoin),
        "{waits:?}"
    );
    let tick = ticker(&h);
    while got_text(&mut arx).await != "다시 드는 중 글" {}
    tick.abort();
}

/// g025 ① 리뷰: 다시 드는 중 줄 선 그룹 글은 다시 들기가 끝내 안 되면(그 사이 그룹에서 빠져 GroupInfo 를 못 받음) 조용히 남지
/// 않고 실패(nack unroutable)로 끝난다.
#[tokio::test(flavor = "multi_thread")]
async fn 다시_드는_중_그룹에서_빠지면_줄_선_글은_실패() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let ek = h.user("erin", 5).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    let (erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    for rx in [&mut arx, &mut brx, &mut drx, &mut erx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "erin@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("erin", &mut erx)] {
        update_of(rx, who, "create").await;
    }
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut erx, "erin", "rename").await;
    erin.shutdown().await;
    drop(erx);
    MlsStore::open(&h.dir.path().join("e.db"), &store_key(5), Arc::new(OsRng))
        .unwrap()
        .set_state(
            gid.as_bytes(),
            lodelai_relay_client::mls_store::GroupState::StalledServer,
            "test",
            1,
        )
        .unwrap();
    let (_erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    wait(&mut erx, "erin ready", |i| {
        matches!(i, Inbound::Ready { .. })
    })
    .await;
    // bob 을 내리고 다시 들기 표시 — 그 사이 alice 의 dave 더하기가 확정 전으로 남는다.
    bob.shutdown().await;
    drop(brx);
    let mut add = gchange(&h, "alice@local", &gid, "add", &[], None);
    add["subject"] = json!("dave@local");
    add["body"] =
        json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) VALUES ('{}', '{gid}', 0)",
            bk.device_id().as_str()
        ),
    );
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    // external commit 이 물러나 로컬 그룹이 없는 때까지.
    for _ in 0..100 {
        if bob.group(&gid).unwrap().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(bob.group(&gid).unwrap().is_none(), "다시 드는 중이 아님");
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        1,
        "아직 확정 전"
    );
    assert!(
        bob.group_send_check(&gid).is_ok(),
        "다시 드는 중 보내기 거절"
    );
    let late = h.chat("bob@local", &format!("+{gid}@{SERVER}"), "빠지는 중 글");
    let late_id = late["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send { message: late }).unwrap();
    // 다시 드는 사이 bob 이 그룹에서 빠졌다(relay 그룹 표) — 확정 뒤 다시 들기는 GroupInfo 를 못 받아 그만둔다.
    relay_sql(
        &h,
        &format!("DELETE FROM group_members WHERE gid = '{gid}' AND user = 'bob'"),
    );
    let tick = ticker(&h);
    wait(
        &mut brx,
        "줄 선 글 실패",
        |i| matches!(i, Inbound::Nack { msg_id, .. } if *msg_id == late_id),
    )
    .await;
    tick.abort();
}

/// g025 ① 판정: 다시 드는 중(relay `mls_rejoin` 표시)으로 붙어 있는 기기는 그룹이 없어 ack·fail 을 못 낸다 — 투표자로 세면
/// 다른 투표자가 없을 때 창 끝 확정(B)이 걸리지 않아 1시간 기다렸다 무효가 됐다. 그 기기는 투표자에서 빼고, 다시 들기가
/// 확정되면(표시 지움) 다음 Commit 부터 다시 투표자다.
#[tokio::test(flavor = "multi_thread")]
async fn 다시_드는_기기는_투표자가_아니고_다시_든_뒤엔_투표자다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let dk = h.user("dave", 4).await;
    let ek = h.user("erin", 5).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    let (erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    for rx in [&mut arx, &mut brx, &mut crx, &mut drx, &mut erx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "erin@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("erin", &mut erx)] {
        update_of(rx, who, "create").await;
    }
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut erx, "erin", "rename").await;
    // bob 을 내리고 alice 가 carol 을 더한다 — 붙은 채 표를 내지 않는 erin 으로 확정 전을 붙잡는다(연결된 투표자가 없으면
    // 배달 직후 확정, #846).
    bob.shutdown().await;
    drop(brx);
    erin.shutdown().await;
    drop(erx);
    let (erin, mut erx) = h.start_with("erin", &ek, 5, "e.db", |c| c.hold_commit_ack = true);
    ready(&mut erx).await;
    // 꺼진 bob 에 다시 들기 표시 — 그 뒤의 Handshake(carol 더하기)는 bob 에 가지 않아 bob 은 그 표를 낼 수 없다. 켜면 external
    // commit 이 확정 전 Commit 때문에 물러나 붙은 채 다시 드는 중.
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) VALUES ('{}', '{gid}', 0)",
            bk.device_id().as_str()
        ),
    );
    let add_of = |who: &str| {
        let mut m = gchange(&h, "alice@local", &gid, "add", &[], None);
        m["subject"] = json!(who);
        m["body"] =
            json!({"enc": "plain", "text": json!({"op": "add", "subject": who}).to_string()});
        m
    };
    let add = add_of("carol@local");
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    for _ in 0..100 {
        if bob.group(&gid).unwrap().is_none() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(bob.group(&gid).unwrap().is_none(), "다시 드는 중이 아님");
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        1,
        "아직 확정 전"
    );
    // erin 이 꺼지면 창 안(시계 그대로)의 tick 에 확정 — 붙어 있는 bob 은 투표자가 아니라 연결 투표자 0(#846). bob 을 세면
    // 확정되지 않는다.
    erin.shutdown().await;
    drop(erx);
    for _ in 0..100 {
        h.app.expire_tick();
        if relay_i64(&h, "SELECT COUNT(*) FROM mls_pending") == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        0,
        "다시 드는 bob 을 투표자로 셈"
    );
    // 확정 뒤 bob 이 다시 든다(external commit 확정 — alice·carol 이 ack). 표시가 지워진다.
    let tick = ticker(&h);
    update_of(&mut arx, "alice", "update").await;
    until_relay(
        &h,
        &format!(
            "SELECT 1 - COUNT(*) FROM mls_rejoin WHERE device_id = '{}'",
            bk.device_id().as_str()
        ),
        1,
    )
    .await;
    for _ in 0..100 {
        if bob.group(&gid).unwrap().is_some()
            && relay_i64(&h, "SELECT COUNT(*) FROM mls_pending") == 0
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tick.abort();
    // 다시 든 bob 은 다시 투표자다: carol 을 내리고 bob 을 표 안 내는 채로 다시 켜면 연결된 투표자는 bob 뿐 — dave 더하기가
    // 확정 전으로 남는다. bob 을 세지 않으면 연결 투표자 0 이라 배달 직후 확정(#846).
    carol.shutdown().await;
    drop(crx);
    bob.shutdown().await;
    drop(brx);
    let (bob, mut brx) = h.start_with("bob", &bk, 2, "b.db", |c| c.hold_commit_ack = true);
    ready(&mut brx).await;
    let add = add_of("dave@local");
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "dave add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    h.app.expire_tick();
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        1,
        "다시 든 bob 은 투표자"
    );
    // bob 이 꺼지면 다음 tick 에 확정 — 다시 켠 bob 은 확정된 add 를 받는다.
    bob.shutdown().await;
    drop(brx);
    for _ in 0..100 {
        h.app.expire_tick();
        if relay_i64(&h, "SELECT COUNT(*) FROM mls_pending") == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    update_of(&mut drx, "dave", "add").await;
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_, st) = update_of(&mut brx, "bob", "add").await;
    assert!(st.members.contains(&"dave@local".to_owned()), "{st:?}");
}

/// 11-04: 다시 들기(external commit, op update)가 확정된 동안 꺼져 있던 멤버가 다시 켜면, 접속 때 오는 지난 결과(commit_final)가
/// 쌓인 봉투보다 먼저 와도 그 Commit 을 확정으로 받아 뒤 글을 연다. 예전엔 update 봉투에 group_seq 가 없어 쥔 채 확정을 영영 기다리며
/// 앞 epoch 에 남았다('Message epoch differs').
#[tokio::test(flavor = "multi_thread")]
async fn 다시_들기_동안_꺼져_있던_멤버도_뒤_글을_연다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    for rx in [&mut arx, &mut brx, &mut crx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let to = format!("+{gid}@{SERVER}");
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &to, "처음"),
        })
        .unwrap();
    while got_text(&mut crx).await != "처음" {}
    carol.shutdown().await;
    drop(crx);
    bob.shutdown().await;
    drop(brx);
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) VALUES ('{}', '{gid}', 0)",
            bk.device_id().as_str()
        ),
    );
    let tick = ticker(&h);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    update_of(&mut arx, "alice", "update").await;
    until_relay(
        &h,
        &format!(
            "SELECT 1 - COUNT(*) FROM mls_rejoin WHERE device_id = '{}'",
            bk.device_id().as_str()
        ),
        1,
    )
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &to, "다시 든 뒤"),
    })
    .unwrap();
    while got_text(&mut arx).await != "다시 든 뒤" {}
    tick.abort();
    // carol 이 다시 켠다 — 접속 때 다시 들기의 commit_final 이 쌓인 봉투(다시 들기 Commit·뒤 글)보다 먼저 온다.
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    while got_text(&mut crx).await != "다시 든 뒤" {}
    drop(alice);
}

/// 묶음 22 h4 §7: 새 기기가 devcert 를 받으면 relay 가 내 다른 기기에 `add_device` duty 를 주고, 그 기기가 내가 든 그룹(group
/// 종류는 `update` Commit, pair 는 기기 단위 Add)에 새 기기를 넣는다 — 그 뒤 새 기기도 두 대화의 글을 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn 새_기기는_duty_로_내_그룹과_1대1_에_들어간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    let tick = ticker(&h);
    update_of(&mut brx, "bob", "create").await;

    let b2k = DeviceKeys::generate(&[6; 64]);
    let b2 = DeviceInfo::of("bob", None, &b2k);
    bob.plant_own_device(&b2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &b2, true)
        .await
        .unwrap();
    let (bob2, mut b2rx) = h.start("bob", &b2k, 6, "b2.db");
    ready(&mut b2rx).await;
    // 새 기기의 잎이 그룹에 들어간 확정(update — 화면 줄 없는 상태 갱신).
    update_of(&mut arx, "alice", "update").await;

    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "그룹에"),
        })
        .unwrap();
    assert_eq!(got_text(&mut b2rx).await, "그룹에");
    // pair: 새 기기가 보낸 것을 alice 가 열면 alice 도 그 Add 를 처리했다 — 그 뒤 alice 의 글은 새 기기에도.
    bob2.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "새 기기에서"),
    })
    .unwrap();
    assert_eq!(got_text(&mut arx).await, "새 기기에서");
    // 내가 보낸 글은 내 다른 기기에도(§7) — bob1 은 b2 가 alice 에게 보낸 것을 열어 받는다(코어가 보낸 글 사본으로).
    while got_text(&mut brx).await != "새 기기에서" {}
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "둘에게"),
        })
        .unwrap();
    assert_eq!(got_text(&mut b2rx).await, "둘에게");

    // 폐기: relay 가 남은 잎에 remove_device duty — 그 잎이 빠진 확정(update) 뒤에도 남은 기기끼리 두 대화가 그대로 된다.
    bob.revoke_other_device(b2k.device_id().as_str(), Duration::from_secs(10))
        .await
        .unwrap();
    update_of(&mut arx, "alice", "update").await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "뺀 뒤 그룹"),
        })
        .unwrap();
    // bob1 은 앞의 글도 받았다 — 그것들을 지나 이 글까지.
    while got_text(&mut brx).await != "뺀 뒤 그룹" {}
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "뺀 뒤 둘"),
    })
    .unwrap();
    while got_text(&mut arx).await != "뺀 뒤 둘" {}
    tick.abort();
}

/// 0.3.0 관문 B18 보안 리뷰: group Commit 의 확정 전 창 안에 Add 대상이 폐기되면 relay 는 remove_device 일감을 만들지
/// 않는다(폐기 때 그 잎이 아직 없다). 그 Add 를 받아들인 멤버가 확정 뒤 일감 없이도 그 잎을 빼는 Commit 을 낸다.
#[tokio::test(flavor = "multi_thread")]
async fn 확정_전에_폐기된_새_기기_잎은_받아들인_멤버가_일감_없이_뺀다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    update_of(&mut crx, "carol", "create").await;
    // carol 은 붙은 채 표를 내지 않는다 — 새 기기 Add 가 확정 전으로 남는다.
    carol.shutdown().await;
    drop(crx);
    let (carol, mut crx) = h.start_with("carol", &ck, 3, "c.db", |c| c.hold_commit_ack = true);
    ready(&mut crx).await;

    // bob 의 새 기기 b2 — duty Add 가 그룹에 걸린다(확정 전).
    let b2k = DeviceKeys::generate(&[6; 64]);
    let b2 = DeviceInfo::of("bob", None, &b2k);
    bob.plant_own_device(&b2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &b2, true)
        .await
        .unwrap();
    let (bob2, mut b2rx) = h.start("bob", &b2k, 6, "b2.db");
    ready(&mut b2rx).await;
    until_relay(&h, "SELECT COUNT(*) FROM mls_pending", 1).await;
    let b2_group = format!(
        "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group' AND l.device_id = '{}'",
        b2k.device_id().as_str()
    );
    assert_eq!(relay_i64(&h, &b2_group), 0, "아직 확정 전");
    // 그 창 안에 b2 폐기 — 그룹 잎이 아직 아니라 relay 는 그 그룹의 remove_device 일감을 만들지 않는다.
    bob2.shutdown().await;
    drop(b2rx);
    bob.revoke_other_device(b2k.device_id().as_str(), Duration::from_secs(10))
        .await
        .unwrap();
    assert_eq!(
        relay_i64(
            &h,
            &format!(
                "SELECT COUNT(*) FROM mls_duties WHERE task = 'remove_device' AND subject = '{}' AND group_id IN (SELECT group_id FROM mls_groups WHERE kind = 'group')",
                b2k.device_id().as_str()
            )
        ),
        0,
        "그룹엔 일감 없음"
    );
    // carol 이 꺼지면 Add 가 확정된다 — 폐기를 아는 alice·bob 도 받아들이고, 든 잎이 폐기 기기라 스스로 뺀다.
    carol.shutdown().await;
    drop(crx);
    let tick = ticker(&h);
    update_of(&mut arx, "alice", "update").await;
    update_of(&mut arx, "alice", "update").await;
    for _ in 0..100 {
        if relay_i64(&h, &b2_group) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(relay_i64(&h, &b2_group), 0, "폐기 잎이 그룹에 남음");
    // 남은 기기끼리 그룹은 그대로 된다.
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "뺀 뒤 그룹"),
        })
        .unwrap();
    while got_text(&mut brx).await != "뺀 뒤 그룹" {}
    tick.abort();
}

/// #846 (b): 새 기기(b2)가 서명만 되고 아직 KeyPackage 를 올리지 않았으면 bob1 의 duty Add 는 KP 없음으로 물러선다(2·4·8·16초…).
/// b2 가 붙어 KP 를 올리면(relay 가 같은 duty 를 다시 주거나 내 기기 접속이 바뀐 디렉터리) 남은 물러섬을 기다리지 않고 곧 Add 한다.
#[tokio::test(flavor = "multi_thread")]
async fn kp_없어_물러선_duty_add_는_새_기기가_붙으면_곧_다시() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    let tick = ticker(&h);
    update_of(&mut brx, "bob", "create").await;

    // 같은 ms 등록은 뿌리 동률(다른 시험과 같은 관례 — relay created_ms 고침 전).
    h.fx.clock.advance(1000);
    let b2k = DeviceKeys::generate(&[7; 64]);
    let b2 = DeviceInfo::of("bob", None, &b2k);
    bob.plant_own_device(&b2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &b2, true)
        .await
        .unwrap();
    // b2 는 아직 안 붙음 — bob1 의 Add 는 KP 없음으로 2·4·8초 물러선다(다음은 16초 뒤).
    tokio::time::sleep(Duration::from_secs(15)).await;
    let t0 = std::time::Instant::now();
    let (_bob2, mut b2rx) = h.start("bob", &b2k, 7, "b2.db");
    ready(&mut b2rx).await;
    update_of(&mut arx, "alice", "update").await;
    let took = t0.elapsed();
    assert!(
        took < Duration::from_secs(8),
        "b2 가 붙은 뒤 {took:?} — 남은 물러섬(16초)을 기다렸다"
    );
    tick.abort();
}

/// #846 실기(갤럭시): 다른 멤버(alice)가 꺼져 있을 때 내 맥(bob1)이 duty `add_device` 로 새 폰(b2)을 그룹에 넣으면, 이름을
/// 다시 보낼 기기로 고른 alice 가 없어도 Commit 을 낸 bob1 이 확정 뒤 다시 보낸다 — 새 폰이 그룹 이름을 안다.
#[tokio::test(flavor = "multi_thread")]
async fn 다른_멤버가_꺼져도_duty_로_든_새_기기는_그룹_이름을_받는다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    let tick = ticker(&h);
    update_of(&mut brx, "bob", "create").await;
    let (_, st) = update_of(&mut brx, "bob", "rename").await;
    assert_eq!(st.name, "팀");
    alice.shutdown().await;

    let b2k = DeviceKeys::generate(&[6; 64]);
    let b2 = DeviceInfo::of("bob", None, &b2k);
    bob.plant_own_device(&b2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &b2, true)
        .await
        .unwrap();
    let (_bob2, mut b2rx) = h.start("bob", &b2k, 6, "b2.db");
    // #846 ①: 접속 때 relay `groups` 를 받으면 아직 들지 못한 그룹 수(1), duty Add 의 Welcome 으로 들면 0.
    wait(
        &mut b2rx,
        "bob2 들어가는 중 1",
        |i| matches!(i, Inbound::GroupsJoining { missing } if missing.len() == 1),
    )
    .await;
    wait(
        &mut b2rx,
        "bob2 들어가는 중 0",
        |i| matches!(i, Inbound::GroupsJoining { missing } if missing.is_empty()),
    )
    .await;
    let (_, st) = update_of(&mut b2rx, "bob2", "rename").await;
    assert_eq!(st.name, "팀");
    tick.abort();
}

/// 묶음 22 h4 §7 주기 Update: 내 응용 메시지가 정한 수에 닿으면 내 잎 Update 를 낸다 — group 은 `update` 확정(상대에게 상태 갱신),
/// pair 는 기기 단위 Commit. 그 뒤에도 양쪽 글이 그대로 열린다.
#[tokio::test(flavor = "multi_thread")]
async fn 보낸_수가_차면_주기_update() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start_with("alice", &ak, 1, "a.db", |c| {
        c.update_every_msgs = 2;
        c.update_check = Duration::ZERO;
    });
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    for t in ["하나", "둘"] {
        alice
            .enqueue(&Outgoing::Send {
                message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), t),
            })
            .unwrap();
        assert_eq!(got_text(&mut brx).await, t);
    }
    update_of(&mut brx, "bob", "update").await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "update 뒤"),
    })
    .unwrap();
    while got_text(&mut arx).await != "update 뒤" {}

    for t in ["1:1 하나", "1:1 둘", "1:1 셋"] {
        alice
            .enqueue(&Outgoing::Send {
                message: h.chat("alice@local", "bob@local", t),
            })
            .unwrap();
        assert_eq!(got_text(&mut brx).await, t);
    }
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "1:1 답"),
    })
    .unwrap();
    while got_text(&mut arx).await != "1:1 답" {}
    tick.abort();
}

/// 11-04: 위 고침 전 relay 에서 이미 막힌 기기(다시 들기 Commit 을 쥔 채 확정을 기다림 — 봉투 group_seq 를 비워 만든다)도 손 없이
/// 풀린다. `then_add` 가 거짓이면 다음 접속 때 relay 가 다시 주는 마지막 결과로 쥔 Commit 을 merge 하고, 참이면 그 사이 확정된
/// 다른 add 를 받지 못해 다시 들어간다. 어느 쪽이든 그 뒤 글을 연다.
async fn 막힌_기기가_풀린다(then_add: bool) {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let dk = h.user("dave", 4).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    for rx in [&mut arx, &mut brx, &mut crx, &mut drx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let to = format!("+{gid}@{SERVER}");
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    carol.shutdown().await;
    drop(crx);
    bob.shutdown().await;
    drop(brx);
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) VALUES ('{}', '{gid}', 0)",
            bk.device_id().as_str()
        ),
    );
    let tick = ticker(&h);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    update_of(&mut arx, "alice", "update").await;
    until_relay(&h, "SELECT 1 - COUNT(*) FROM mls_pending", 1).await;
    tick.abort();
    // 고침 전 relay 처럼 확정된 다시 들기 봉투의 group_seq 를 비운다.
    relay_sql(
        &h,
        &format!(
            "UPDATE envelopes SET group_seq = NULL WHERE message LIKE '%\"group_op\":\"update\"%' AND message LIKE '%{gid}%'"
        ),
    );
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &to, "막힌 동안"),
    })
    .unwrap();
    while got_text(&mut arx).await != "막힌 동안" {}
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    wait(&mut crx, "막힌 글", |i| {
        matches!(i, Inbound::Unreadable { .. })
    })
    .await;
    carol.shutdown().await;
    drop(crx);
    if then_add {
        let mut add = gchange(&h, "alice@local", &gid, "add", &[], None);
        add["subject"] = json!("dave@local");
        add["body"] = json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
        let tick = ticker(&h);
        alice
            .enqueue(&Outgoing::GroupChange { message: add })
            .unwrap();
        update_of(&mut drx, "dave", "add").await;
        until_relay(&h, "SELECT 1 - COUNT(*) FROM mls_pending", 1).await;
        let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
        // carol 은 add 를 열지 못해 다시 든다 — alice 에게 update.
        update_of(&mut arx, "alice", "update").await;
        until_relay(&h, "SELECT 1 - COUNT(*) FROM mls_pending", 1).await;
        tick.abort();
        bob.enqueue(&Outgoing::Send {
            message: h.chat("bob@local", &to, "풀린 뒤"),
        })
        .unwrap();
        while got_text(&mut crx).await != "풀린 뒤" {}
    } else {
        let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
        wait(&mut crx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
        bob.enqueue(&Outgoing::Send {
            message: h.chat("bob@local", &to, "풀린 뒤"),
        })
        .unwrap();
        while got_text(&mut crx).await != "풀린 뒤" {}
    }
    drop((alice, brx));
}

#[tokio::test(flavor = "multi_thread")]
async fn 막힌_기기는_다시_접속하면_풀린다() {
    막힌_기기가_풀린다(false).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn 막힌_기기는_뒤_add_가_확정돼도_다시_들어_풀린다() {
    막힌_기기가_풀린다(true).await;
}

/// 11-04: 주기 Update(op update)가 확정된 동안 꺼져 있던 멤버도 다시 켜면 뒤 글을 연다 — 다시 들기와 같은 구멍(update 봉투에
/// group_seq 가 없어 접속 때 먼저 온 결과를 흘리고 그 Commit 을 쥔 채 남음).
#[tokio::test(flavor = "multi_thread")]
async fn 주기_update_동안_꺼져_있던_멤버도_뒤_글을_연다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start_with("alice", &ak, 1, "a.db", |c| {
        c.update_every_msgs = 2;
        c.update_check = Duration::ZERO;
    });
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    for rx in [&mut arx, &mut brx, &mut crx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let to = format!("+{gid}@{SERVER}");
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("carol", &mut crx)] {
        update_of(rx, who, "create").await;
    }
    carol.shutdown().await;
    drop(crx);
    let tick = ticker(&h);
    for t in ["하나", "둘"] {
        alice
            .enqueue(&Outgoing::Send {
                message: h.chat("alice@local", &to, t),
            })
            .unwrap();
        while got_text(&mut brx).await != t {}
    }
    update_of(&mut brx, "bob", "update").await;
    until_relay(&h, "SELECT 1 - COUNT(*) FROM mls_pending", 1).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &to, "update 뒤"),
        })
        .unwrap();
    while got_text(&mut brx).await != "update 뒤" {}
    tick.abort();
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    while got_text(&mut crx).await != "update 뒤" {}
    drop(alice);
}

/// 묶음 22 h4 §5a: relay 가 그 기기 앞 Handshake 를 비우고 `rejoin_needed` 를 주면, 기기는 `group_info.get` → external commit 으로
/// 다시 들어간다(pair 는 ack 로 끝, group 은 2단계 확정 — 상대에게 update). 그 뒤 두 대화가 양쪽으로 그대로 된다.
#[tokio::test(flavor = "multi_thread")]
async fn rejoin_needed_면_external_commit_으로_다시_들어간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    let first = h.chat("alice@local", "bob@local", "처음");
    let first_at =
        lodelai_effects::UnixMillis::parse_rfc3339(first["created_at"].as_str().unwrap())
            .unwrap()
            .0;
    alice.enqueue(&Outgoing::Send { message: first }).unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    bob.shutdown().await;
    drop(brx);

    // 보관 상한으로 비운 것처럼 bob 기기의 모든 그룹에 rejoin 표시.
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) SELECT device_id, group_id, 0 FROM mls_leaves WHERE device_id = '{}'",
            bk.device_id().as_str()
        ),
    );
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    // ready() 는 Directory 까지 다른 것을 버린다 — 디렉터리 답이 늦으면 다시 들어간 대화의 ok 를 삼킨다.
    wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    update_of(&mut arx, "alice", "update").await;
    // §12-27 ⓐ: 다시 들어간 대화마다 ok + lost_since — 1:1 은 마지막으로 연 글의 시각, 연 글이 없는 그룹은 rejoin_needed 받은 때.
    let mut lost = std::collections::BTreeMap::new();
    while lost.len() < 2 {
        let sync = |i: &Inbound| matches!(i, Inbound::ConversationSync { state: None, .. });
        let Inbound::ConversationSync {
            conversation,
            lost_since,
            ..
        } = wait(&mut brx, "다시 들어간 대화", sync).await
        else {
            unreachable!()
        };
        lost.insert(conversation, lost_since);
    }
    assert_eq!(lost["alice@local"], Some(first_at), "{lost:?}");
    assert!(
        lost[&format!("+{gid}@{SERVER}")].is_some_and(|t| t >= first_at),
        "{lost:?}"
    );

    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "다시 1:1"),
    })
    .unwrap();
    while got_text(&mut arx).await != "다시 1:1" {}
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "다시 그룹"),
    })
    .unwrap();
    while got_text(&mut arx).await != "다시 그룹" {}
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "받았어"),
        })
        .unwrap();
    while got_text(&mut brx).await != "받았어" {}

    // 다시 켠 뒤 그룹에만 rejoin_needed 가 또 와도(#577 — 겹친 다시 들어가기 막기 뒤) 한 번 다시 들고 그룹을 잃지 않는다.
    bob.shutdown().await;
    drop(brx);
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) SELECT device_id, group_id, 0 FROM mls_leaves WHERE device_id = '{}' AND group_id = '{gid}'",
            bk.device_id().as_str()
        ),
    );
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    wait(&mut brx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    update_of(&mut arx, "alice", "update").await;
    wait(&mut brx, "다시 들어간 그룹", |i| {
        matches!(i, Inbound::ConversationSync { state: None, .. })
    })
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "겹친 뒤 그룹"),
    })
    .unwrap();
    while got_text(&mut arx).await != "겹친 뒤 그룹" {}
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "그룹 답"),
        })
        .unwrap();
    while got_text(&mut brx).await != "그룹 답" {}
    tick.abort();
}

/// 묶음 22 §9·§12-23 ②: stalled_server 로 멈춘 1:1 은 '다시 받기'로만 풀린다 — syncing 을 알리고 external commit 으로 다시
/// 들어가면 ok(멈춘 동안 버린 글의 때와 함께), 그 뒤 양쪽으로 주고받는다.
#[tokio::test(flavor = "multi_thread")]
async fn 다시_받기로_멈춘_대화에_다시_들어간다() {
    use lodelai_relay_client::mls_store::GroupState;
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    bob.shutdown().await;
    drop(brx);
    let gid = lodelai_relay_client::mls::pair_group_id("alice", "bob");
    {
        let st =
            MlsStore::open(&h.dir.path().join("b.db"), &store_key(2), Arc::new(OsRng)).unwrap();
        st.set_state(&gid, GroupState::StalledServer, "user_leaves_left", 1)
            .unwrap();
        st.put_lost(&gid, 7).unwrap();
    }
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let sync = |i: &Inbound| matches!(i, Inbound::ConversationSync { .. });
    let Inbound::ConversationSync { state, .. } = wait(&mut brx, "멈춤 알림", sync).await
    else {
        unreachable!()
    };
    assert_eq!(state, Some(GroupState::StalledServer));
    bob.rejoin_conversation("alice@local").unwrap();
    let Inbound::ConversationSync { state, .. } = wait(&mut brx, "syncing", sync).await else {
        unreachable!()
    };
    assert_eq!(state, Some(GroupState::Syncing));
    let Inbound::ConversationSync {
        state, lost_since, ..
    } = wait(&mut brx, "ok", sync).await
    else {
        unreachable!()
    };
    assert_eq!((state, lost_since), (None, Some(7)));
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "다시"),
    })
    .unwrap();
    while got_text(&mut arx).await != "다시" {}
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "받았어"),
        })
        .unwrap();
    while got_text(&mut brx).await != "받았어" {}
    tick.abort();
}

/// 묶음 22 h4 ⓒ(§7·ADR §4): 마지막 수단 KeyPackage(여럿이 나눠 쓰는 init 키)로 들어온 기기는 첫 보내기 전에 Update 한다 —
/// pair 는 기기 단위 Commit(epoch 2), group 은 update 확정(epoch 2).
#[tokio::test(flavor = "multi_thread")]
async fn 마지막_수단_keypackage_로_들어오면_바로_update() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    // bob 은 마지막 수단 하나만 올린다.
    let (_bob, mut brx) = h.start_with("bob", &bk, 2, "b.db", |c| c.key_package_target = 0);
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    until_relay(
        &h,
        "SELECT MAX(epoch) FROM mls_groups WHERE kind = 'pair'",
        2,
    )
    .await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut arx, "alice", "update").await;
    until_relay(
        &h,
        "SELECT MAX(epoch) FROM mls_groups WHERE kind = 'group'",
        2,
    )
    .await;
    tick.abort();
}

/// 묶음 22 h4 ⓓ(§7): 내 다른 기기가 모두 꺼져 duty Add 를 낼 기기가 없으면, 새 기기가 잎 자격을 얻고 30분 뒤 스스로
/// external commit 으로 pair·group 에 들어간다 — 그 뒤 상대 글을 받는다.
#[tokio::test(flavor = "multi_thread")]
async fn 다른_기기가_없으면_새_기기가_스스로_들어간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;

    // a1 이 a2 의 devcert 를 서명한 뒤 꺼진다 — duty Add 를 낼 기기가 없다.
    let a2k = DeviceKeys::generate(&[5; 64]);
    let a2 = DeviceInfo::of("alice", None, &a2k);
    alice.plant_own_device(&a2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &a2, true)
        .await
        .unwrap();
    let signer = format!("\"signer\":\"{}\"", ak.device_id().as_str());
    wait(
        &mut arx,
        "a2 devcert",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&signer)),
    )
    .await;
    alice.shutdown().await;
    let (_a2, mut a2rx) = h.start_with("alice", &a2k, 5, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(1800);
        c.update_check = Duration::ZERO;
    });
    ready(&mut a2rx).await;
    // 시계가 30분을 넘기면 group 다시 들어가기 확정(update)이 bob 에게.
    update_of(&mut brx, "bob", "update").await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "그룹 새 기기"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "그룹 새 기기" {}
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            a2k.device_id().as_str()
        ),
        1,
    )
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "1:1 새 기기"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "1:1 새 기기" {}
    tick.abort();
}

/// g025f A(0.2.5): 새 기기를 확인한 옛 기기가 바로 꺼지면 있던 1:1 의 add_device 를 낼 기기가 없다(상대는 후보가 아님) — relay 가
/// 1분 뒤 새 기기에 다시 들기 표시를 주어 `orphan_wait`(여기선 1년) 없이 스스로 들고, 그 뒤 1:1 글이 새 기기에 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 옛_기기가_확인_뒤_바로_꺼지면_새_기기가_있던_1대1_에_든다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "처음"),
    })
    .unwrap();
    assert_eq!(got_text(&mut arx).await, "처음");

    let a2k = DeviceKeys::generate(&[5; 64]);
    let a2 = DeviceInfo::of("alice", None, &a2k);
    alice.plant_own_device(&a2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &a2, true)
        .await
        .unwrap();
    let signer = format!("\"signer\":\"{}\"", ak.device_id().as_str());
    wait(
        &mut arx,
        "a2 devcert",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&signer)),
    )
    .await;
    alice.shutdown().await;
    let (_a2, mut a2rx) = h.start_with("alice", &a2k, 5, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            a2k.device_id().as_str()
        ),
        1,
    )
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "새 기기로"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "새 기기로" {}
    tick.abort();
}

/// g025g(0.2.5): 새 기기가 1:1 에 들기 전 틈에 보낸 글(꺼진 옛 기기에만 실림)은, 새 잎이 들 때 보낸 쪽에 기기 바뀜 실패와
/// `RecipientRejoined` 가 온다. 같은 msg_id 로 다시 보내면 새 기기에 간다. 이미 옛 기기가 받은 글과 든 뒤 보낸 글은 표시하지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 새_기기가_들기_전_틈에_보낸_1대1_글은_다시_보내면_새_기기에_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    let first = h.chat("bob@local", "alice@local", "처음");
    let first_id = first["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send { message: first }).unwrap();
    assert_eq!(got_text(&mut arx).await, "처음");

    let a2k = DeviceKeys::generate(&[5; 64]);
    let a2 = DeviceInfo::of("alice", None, &a2k);
    alice.plant_own_device(&a2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &a2, true)
        .await
        .unwrap();
    let signer = format!("\"signer\":\"{}\"", ak.device_id().as_str());
    wait(
        &mut arx,
        "a2 devcert",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&signer)),
    )
    .await;
    alice.shutdown().await;
    // 틈: a2 가 아직 안 들었다 — 꺼진 a1 에만 실린다.
    let gap = h.chat("bob@local", "alice@local", "틈");
    let gap_id = gap["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send {
        message: gap.clone(),
    })
    .unwrap();
    until_relay(
        &h,
        &format!("SELECT COUNT(*) FROM envelopes WHERE msg_id = '{gap_id}'"),
        1,
    )
    .await;
    let (_a2, mut a2rx) = h.start_with("alice", &a2k, 5, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    // 새 잎이 들면: 틈 글만 기기 바뀜 실패, 상대 새 잎 알림.
    let mut failed = Vec::new();
    let mut rejoined = false;
    while !(rejoined && failed.contains(&gap_id)) {
        match wait(&mut brx, "기기 바뀜·새 잎", |i| {
            matches!(i, Inbound::RecipientRejoined { .. })
                || matches!(i, Inbound::Status { fail_reason, .. }
                    if fail_reason.as_deref() == Some("recipient_device_changed"))
        })
        .await
        {
            Inbound::RecipientRejoined { user } => {
                assert_eq!(user, "alice");
                rejoined = true;
            }
            Inbound::Status { msg_id, .. } => failed.push(msg_id),
            _ => {}
        }
    }
    assert!(
        !failed.contains(&first_id),
        "이미 받은 글은 표시하지 않는다"
    );
    // 들고 난 뒤 보낸 글은 바로 간다(표시 없음).
    let after = h.chat("bob@local", "alice@local", "든 뒤");
    let after_id = after["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send { message: after }).unwrap();
    while got_text(&mut a2rx).await != "든 뒤" {}
    // 같은 msg_id 로 다시 보내면(코어가 하는 일) 새 기기에 간다.
    bob.enqueue(&Outgoing::Send { message: gap }).unwrap();
    while got_text(&mut a2rx).await != "틈" {}
    assert_eq!(
        relay_i64(
            &h,
            &format!(
                "SELECT COUNT(*) FROM device_changed WHERE msg_id IN ('{first_id}', '{after_id}')"
            )
        ),
        0
    );
    tick.abort();
}

/// g025f B(0.2.5): 같은 기기(같은 키)가 로컬 데이터만 잃고 다시 붙으면 첫 올리기가 `reset` 이라 relay 의 옛 KeyPackage 가 지워지고
/// (처음 보내는 사람의 1:1 이 열림), relay 가 그 기기가 잎인 그룹에 다시 들기 표시를 주어 있던 1:1 도 다시 들어 뒤 글을 연다.
#[tokio::test(flavor = "multi_thread")]
async fn 같은_기기가_데이터를_잃고_다시_붙으면_새_1대1_과_있던_1대1_을_연다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let tick = ticker(&h);
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    bob.shutdown().await;
    // 같은 키, 빈 데이터.
    let (_bob2, mut b2rx) = h.start("bob", &bk, 2, "b-again.db");
    ready(&mut b2rx).await;
    carol
        .enqueue(&Outgoing::Send {
            message: h.chat("carol@local", "bob@local", "처음 보내는 사람"),
        })
        .unwrap();
    while got_text(&mut b2rx).await != "처음 보내는 사람" {}
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "있던 대화"),
        })
        .unwrap();
    while got_text(&mut b2rx).await != "있던 대화" {}
    tick.abort();
}

/// #577 시험 16b(§9 ①): 내 다른 폐기 안 된 기기가 없으면(옛 기기가 끊긴 뒤 새 기기 혼자) `orphan_wait` 를 기다리지 않고 디렉터리를
/// 받는 즉시 스스로 들어간다 — 1년으로 둬도 든다. 다른 내 기기가 남아 있으면 지금처럼 기다린다(위 시험들).
/// a2 가 처음 받은 GroupInfo 에 끊긴 a1 잎이 남아 있으면 external commit 을 만들지 못한다 — bob 이 a1 을 빼 줄 때까지 2초부터
/// 짧게 다시 본다(§9 ③).
#[tokio::test(flavor = "multi_thread")]
async fn 내_다른_기기가_없으면_기다리지_않고_스스로_들어간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");

    // a1 이 a2 의 devcert 를 서명한 뒤 꺼지고, 24시간 뒤 a2 가 a1 을 끊는다(§9 '24h 뒤 직접 끊기') — a2 혼자 남는다.
    let a2k = DeviceKeys::generate(&[5; 64]);
    let a2 = DeviceInfo::of("alice", None, &a2k);
    alice.plant_own_device(&a2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &a2, true)
        .await
        .unwrap();
    let signer = format!("\"signer\":\"{}\"", ak.device_id().as_str());
    wait(
        &mut arx,
        "a2 devcert",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&signer)),
    )
    .await;
    alice.shutdown().await;
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 5, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    until_peer(&a2c, ak.device_id().as_str()).await;
    h.fx.clock.advance(25 * 3_600_000);
    a2c.revoke_other_device(ak.device_id().as_str(), Duration::from_secs(10))
        .await
        .unwrap();
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            a2k.device_id().as_str()
        ),
        1,
    )
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "1:1 새 기기"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "1:1 새 기기" {}
    tick.abort();
}

/// #577 시험 16(§9): 메일 확인 끊기 — 확인받지 못한(pending) 새 기기 a2 가 걸고 relay 시각으로 24h 가 지나면 옛 기기 a1 이
/// by recovery 로 끊기고, a2 는 혼자 남아 기다리지 않고 pair 에 다시 든다 — 그 뒤 bob 의 1:1 글이
/// a2 에 온다. 그룹은 아래 시험.
#[tokio::test(flavor = "multi_thread")]
async fn 메일_확인_끊기가_끝나면_새_기기가_바로_들고_글이_온다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");

    // a2: 같은 계정의 새 기기 — 옛 기기가 확인하지 않았다(pending).
    let a2k = DeviceKeys::generate(&[6; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 6, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    a2c.recover(
        lodelai_relay_client::Recover::Start,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    // 옛 기기 a1 에 막기 카드 재료가 온다.
    wait(&mut arx, "recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 시험 19: 앱을 다시 켜도(인증 직후) 막기 카드 재료가 다시 온다 — 코어는 저장하지 않는다.
    alice.shutdown().await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut arx, "다시 켠 뒤 recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 막지 않고 24h — 옛 기기가 걸기 동안 붙어 있었으니 relay 가 한 번 미루고(#737), 그 24h 뒤 끊는다(by recovery).
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    let revoked = |i: &Inbound| {
        matches!(
            i,
            Inbound::RemovedFromAccount {
                by: lodelai_relay_client::RemovedBy::Recovery,
                at: Some(_)
            }
        )
    };
    wait(&mut arx, "끊김", revoked).await;
    alice.shutdown().await;
    // 끊긴 옛 기기는 다시 켜도 같은 사유로(시험 19·22 — 앱은 지우지 않고 사유를 보인다).
    let (_old, mut orx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut orx, "다시 켠 뒤 끊김", revoked).await;
    let tick = ticker(&h);
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            a2k.device_id().as_str()
        ),
        1,
    )
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "끊기 뒤 1:1"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "끊기 뒤 1:1" {}
    tick.abort();
}

/// #599 ①: 메일 확인 끊기가 끝나는 순간 새 기기 a2 가 꺼져 있었다(device.recovered 를 놓침). relay 는 끊기 완료 때 pair·group 둘에
/// 다시 들기 표시를 남기고, a2 를 다시 켜면 pair·group 에 바로 든다. 이 경우(a2 혼자 남음)는 클라이언트 §9 ①(due_orphan — 혼자면
/// 기다리지 않음)도 접속 직후 같은 일을 하므로, relay ① 을 빼도 드는 것은 같다 — relay ① 이 도는지는 표시 개수로 본다.
#[tokio::test(flavor = "multi_thread")]
async fn 끊기_때_꺼져_있던_새_기기도_다시_켜면_바로_든다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;

    let a2k = DeviceKeys::generate(&[6; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let slow = |c: &mut lodelai_relay_client::Config| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    };
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 6, "a2.db", slow);
    ready(&mut a2rx).await;
    a2c.recover(
        lodelai_relay_client::Recover::Start,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    wait(&mut arx, "recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // a2 는 끊기가 끝나기 전에 꺼진다.
    a2c.shutdown().await;
    drop(a2rx);
    // 옛 기기가 걸기 동안 붙어 있었으니 relay 가 한 번 미루고(#737), 그 24h 뒤 끊는다.
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    wait(&mut arx, "끊김", |i| {
        matches!(
            i,
            Inbound::RemovedFromAccount {
                by: lodelai_relay_client::RemovedBy::Recovery,
                ..
            }
        )
    })
    .await;
    alice.shutdown().await;
    let a2_id = a2k.device_id().as_str().to_owned();
    assert_eq!(
        relay_i64(
            &h,
            &format!("SELECT COUNT(*) FROM mls_rejoin WHERE device_id = '{a2_id}'")
        ),
        2,
        "끊기 완료 때 pair·group 둘에 다시 들기 표시"
    );

    // 다시 켜면 바로 든다.
    let (_a2c, mut a2rx) = h.start_with("alice", &a2k, 6, "a2.db", slow);
    ready(&mut a2rx).await;
    let tick = ticker(&h);
    for kind in ["pair", "group"] {
        until_relay(
            &h,
            &format!(
                "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = '{kind}' AND l.device_id = '{a2_id}'"
            ),
            1,
        )
        .await;
    }
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "다시 켠 뒤 1:1"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "다시 켠 뒤 1:1" {}
    tick.abort();
}

/// #577 시험 16 그룹(§9, 설계 리뷰 🔴): 메일 확인 끊기 — 확인받지 못한(pending) 새 기기 a2 가 걸고 relay 시각으로 24h 가 지나면 옛 기기 a1 이
/// by recovery 로 끊기고, a2 는 혼자 남아 기다리지 않고 pair·group 에 다시 든다(그룹 잎 = {a2, bob}, 남은 일 0) — 그 뒤 bob 의
/// 1:1·그룹 글이 a2 에 온다. 두 명 그룹 {a1, bob} 에서 bob 의 a1 Remove 는 응답할 산 잎이 없으니 relay 가 바로 확정한다(10-29
/// 결함: 폐기된 a1 의 ack 를 기다리다 void 됐음).
#[tokio::test(flavor = "multi_thread")]
async fn 메일_확인_끊기가_끝나면_새_기기가_그룹에도_바로_든다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    // 그룹 {alice, bob} — 끊긴 a1 잎이 GroupInfo 에 남는 경우(리뷰 🔴, 백엔드 재현 6490603738 ③).
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    // 이름은 만든 a1 의 rename 글로만 간다 — 부하에서 그 글이 a1 의 큐에 남은 채 a1 이 끊기면 bob 이 이름을 몰라 아래에서 a2 에
    // 다시 보내지 못한다(시험 전제, 40번 중 2번). bob 이 이름을 안 뒤에 시작한다.
    for _ in 0..100 {
        if bob.group(&gid).unwrap().is_some_and(|g| g.name == "팀") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        bob.group(&gid).unwrap().map(|g| g.name).unwrap_or_default(),
        "팀"
    );

    // a2: 같은 계정의 새 기기 — 옛 기기가 확인하지 않았다(pending).
    let a2k = DeviceKeys::generate(&[6; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 6, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    a2c.recover(
        lodelai_relay_client::Recover::Start,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    // 옛 기기 a1 에 막기 카드 재료가 온다.
    wait(&mut arx, "recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 시험 19: 앱을 다시 켜도(인증 직후) 막기 카드 재료가 다시 온다 — 코어는 저장하지 않는다.
    alice.shutdown().await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut arx, "다시 켠 뒤 recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 막지 않고 24h — 옛 기기가 걸기 동안 붙어 있었으니 relay 가 한 번 미루고(#737), 그 24h 뒤 끊는다(by recovery).
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    let revoked = |i: &Inbound| {
        matches!(
            i,
            Inbound::RemovedFromAccount {
                by: lodelai_relay_client::RemovedBy::Recovery,
                at: Some(_)
            }
        )
    };
    wait(&mut arx, "끊김", revoked).await;
    alice.shutdown().await;
    // 끊긴 옛 기기는 다시 켜도 같은 사유로(시험 19·22 — 앱은 지우지 않고 사유를 보인다).
    let (_old, mut orx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut orx, "다시 켠 뒤 끊김", revoked).await;
    let tick = ticker(&h);
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            a2k.device_id().as_str()
        ),
        1,
    )
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "끊기 뒤 1:1"),
    })
    .unwrap();
    // 그룹 상태(아래에서 확인)가 1:1 글보다 먼저 올 수 있다 — 기다리는 동안 버리지 않고 둔다.
    let mut a2_group = None;
    loop {
        match wait(&mut a2rx, "a2 1:1 글", |i| {
            matches!(i, Inbound::Deliver { .. })
                || matches!(i, Inbound::GroupUpdate { op, .. } if op == "update")
        })
        .await
        {
            Inbound::GroupUpdate { state, .. } => a2_group = Some(state),
            Inbound::Deliver { message, ack } => {
                ack.ack();
                if message.pointer("/body/text").and_then(Value::as_str) == Some("끊기 뒤 1:1") {
                    break;
                }
            }
            _ => unreachable!(),
        }
    }
    // 그룹: 잎 = {a2, bob}, 남은 일 0, 그 뒤 bob 의 그룹 글이 a2 에.
    let a2_id = a2k.device_id().as_str().to_owned();
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group' AND l.device_id = '{a2_id}'"
        ),
        1,
    )
    .await;
    let group_leaves = |h: &Harness| {
        relay_i64(
            h,
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group'",
        )
    };
    let group_duties = |h: &Harness| {
        relay_i64(
            h,
            "SELECT COUNT(*) FROM mls_duties d JOIN mls_groups g ON g.group_id = d.group_id WHERE g.kind = 'group'",
        )
    };
    for _ in 0..100 {
        if group_leaves(&h) == 2 && group_duties(&h) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(group_leaves(&h), 2, "그룹 잎 = {{a2, bob}}");
    assert_eq!(group_duties(&h), 0, "남은 일 0");
    // a2 앱도 그룹을 안다(external commit 결과가 a2 에 와야 그룹 상태가 오른다).
    let state = match a2_group {
        Some(state) => state,
        None => update_of(&mut a2rx, "a2", "update").await.1,
    };
    let mut members = state.members.clone();
    members.sort();
    assert_eq!(members, ["alice@local", "bob@local"], "{state:?}");
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "끊기 뒤 그룹"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "끊기 뒤 그룹" {}
    // 그룹 이름(#577 실기 확인 — external commit 으로 든 새 기기는 이름을 몰라 사이드바 '?'): 전부터 있던 잎 bob 이 다시 보낸다.
    let mut name = String::new();
    for _ in 0..100 {
        name = a2c.group(&gid).unwrap().map(|g| g.name).unwrap_or_default();
        if name == "팀" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(name, "팀", "a2 가 그룹 이름을 안다");
    tick.abort();
}

/// #577 실기 확인 ❌-1 재현: 세 명 그룹 {alice, bob, carol}(캐럴이 ack 해 relay void 는 비켜 감). 옛 잎이 먼저 빠진 사용자의 새
/// 기기 a2 가 external commit 으로 스스로 든다 — relay 는 직전 epoch 에 잎이 없어도 지금 그룹 멤버면 받는다(10-29 결함:
/// invalid_commit 으로 거절). 그 뒤 bob 의 1:1·그룹 글이 a2 에 온다.
#[tokio::test(flavor = "multi_thread")]
async fn 메일_확인_끊기가_끝나면_새_기기가_세_명_그룹에도_바로_든다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut crx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    // 그룹 {alice, bob} — 끊긴 a1 잎이 GroupInfo 에 남는 경우(리뷰 🔴, 백엔드 재현 6490603738 ③).
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    update_of(&mut crx, "carol", "create").await;

    // a2: 같은 계정의 새 기기 — 옛 기기가 확인하지 않았다(pending).
    let a2k = DeviceKeys::generate(&[6; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 6, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    a2c.recover(
        lodelai_relay_client::Recover::Start,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    // 옛 기기 a1 에 막기 카드 재료가 온다.
    wait(&mut arx, "recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 시험 19: 앱을 다시 켜도(인증 직후) 막기 카드 재료가 다시 온다 — 코어는 저장하지 않는다.
    alice.shutdown().await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut arx, "다시 켠 뒤 recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 막지 않고 24h — 옛 기기가 걸기 동안 붙어 있었으니 relay 가 한 번 미루고(#737), 그 24h 뒤 끊는다(by recovery).
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    let revoked = |i: &Inbound| {
        matches!(
            i,
            Inbound::RemovedFromAccount {
                by: lodelai_relay_client::RemovedBy::Recovery,
                at: Some(_)
            }
        )
    };
    wait(&mut arx, "끊김", revoked).await;
    alice.shutdown().await;
    // 끊긴 옛 기기는 다시 켜도 같은 사유로(시험 19·22 — 앱은 지우지 않고 사유를 보인다).
    let (_old, mut orx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut orx, "다시 켠 뒤 끊김", revoked).await;
    let tick = ticker(&h);
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            a2k.device_id().as_str()
        ),
        1,
    )
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "끊기 뒤 1:1"),
    })
    .unwrap();
    // 그룹 상태(아래에서 확인)가 1:1 글보다 먼저 올 수 있다 — 기다리는 동안 버리지 않고 둔다.
    let mut a2_group = None;
    loop {
        match wait(&mut a2rx, "a2 1:1 글", |i| {
            matches!(i, Inbound::Deliver { .. })
                || matches!(i, Inbound::GroupUpdate { op, .. } if op == "update")
        })
        .await
        {
            Inbound::GroupUpdate { state, .. } => a2_group = Some(state),
            Inbound::Deliver { message, ack } => {
                ack.ack();
                if message.pointer("/body/text").and_then(Value::as_str) == Some("끊기 뒤 1:1") {
                    break;
                }
            }
            _ => unreachable!(),
        }
    }
    // 그룹: 잎 = {a2, bob}, 남은 일 0, 그 뒤 bob 의 그룹 글이 a2 에.
    let a2_id = a2k.device_id().as_str().to_owned();
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group' AND l.device_id = '{a2_id}'"
        ),
        1,
    )
    .await;
    let group_leaves = |h: &Harness| {
        relay_i64(
            h,
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group'",
        )
    };
    let group_duties = |h: &Harness| {
        relay_i64(
            h,
            "SELECT COUNT(*) FROM mls_duties d JOIN mls_groups g ON g.group_id = d.group_id WHERE g.kind = 'group'",
        )
    };
    for _ in 0..100 {
        if group_leaves(&h) == 3 && group_duties(&h) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(group_leaves(&h), 3, "그룹 잎 = {{a2, bob, carol}}");
    assert_eq!(group_duties(&h), 0, "남은 일 0");
    // a2 앱도 그룹을 안다(10-29 실기 확인 ❌: relay 가 잎으로 넣었어도 external commit 결과가 a2 에 안 가 그룹이 화면에 없었다) —
    // 글이 오기 전에 그룹 상태가 먼저 온다.
    let state = match a2_group {
        Some(state) => state,
        None => update_of(&mut a2rx, "a2", "update").await.1,
    };
    let mut members = state.members.clone();
    members.sort();
    assert_eq!(
        members,
        ["alice@local", "bob@local", "carol@local"],
        "{state:?}"
    );
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "끊기 뒤 그룹"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "끊기 뒤 그룹" {}
    // 그룹 이름(#577 재검 6bd638802 ❌1 — 세 명 그룹에서 external commit 으로 든 새 기기의 이름이 빈 값): 전부터 있던 잎 중 하나가
    // 다시 보낸다.
    let mut name = String::new();
    for _ in 0..100 {
        name = a2c.group(&gid).unwrap().map(|g| g.name).unwrap_or_default();
        if name == "팀" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(name, "팀", "a2 가 그룹 이름을 안다");
    tick.abort();
}

/// #577 재검 6bd638802 ❌1 재현('지금 끊기' 길): 옛 기기 a1 이 새 기기 a2 를 서명하고, 그룹에 a2 잎이 보이자마자(앱의
/// recover_cut_self 와 같은 순서) 스스로 끊는다. a1 이 넣은 a2 잎의 Welcome 은 트리에 끊긴 a1 이 있어 a2 가 거절하고, 남은
/// 멤버가 a1 을 뺀 뒤 a2 는 external commit 으로 **자기 옛 잎을 갈아 끼워** 든다 — 같은 기기라 '전에 없던 잎' 비교로는 새로 든
/// 것을 못 가려 그룹 이름을 아무도 다시 보내지 않았다(이름 빈 값·seq 0).
#[tokio::test(flavor = "multi_thread")]
async fn 지금_끊기로_든_새_기기도_그룹_이름을_안다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    update_of(&mut crx, "carol", "create").await;

    let a2k = DeviceKeys::generate(&[7; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 7, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    a2c.recover(
        lodelai_relay_client::Recover::Start,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    let a2_id = a2k.device_id().as_str().to_owned();
    wait(
        &mut arx,
        "recover_against",
        |i| matches!(i, Inbound::RecoverAgainst { requester, .. } if *requester == a2_id),
    )
    .await;
    // 실제 재검에서 a2 는 a1 이 끊긴 뒤에 그 Welcome 을 열었다 — 그 순서가 되게 끊는 동안 a2 를 꺼 둔다.
    a2c.shutdown().await;
    let tick = ticker(&h);
    // '내가 걸었어요 — 지금 끊기': 서명 → 그룹마다 a2 잎(최대 10초) → 스스로 폐기.
    alice.trust_device("alice", &a2_id).unwrap();
    for _ in 0..100 {
        if alice.groups_missing_leaf(&a2_id) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    alice.revoke_device(Duration::from_secs(10)).await.unwrap();
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 7, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    // a2 가 그룹에 들고(relay 잎), 그룹 이름을 안다.
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group' AND l.device_id = '{a2_id}'"
        ),
        1,
    )
    .await;
    let mut name = String::new();
    for _ in 0..300 {
        name = a2c.group(&gid).unwrap().map(|g| g.name).unwrap_or_default();
        if name == "팀" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(name, "팀", "a2 가 그룹 이름을 안다");
    // 끊긴 a1 잎은 그룹에서 빠진다(남은 멤버·든 a2 중 누가 빼든).
    let a1_id = ak.device_id().as_str().to_owned();
    let a1_leaves = |h: &Harness| {
        relay_i64(
            h,
            &format!(
                "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group' AND l.device_id = '{a1_id}'"
            ),
        )
    };
    for _ in 0..100 {
        if a1_leaves(&h) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(a1_leaves(&h), 0, "끊긴 a1 잎이 빠진다");
    // 그 뒤 캐럴의 그룹 글을 a2 가 읽는다.
    carol
        .enqueue(&Outgoing::Send {
            message: h.chat("carol@local", &format!("+{gid}@{SERVER}"), "끊은 뒤 그룹"),
        })
        .unwrap();
    while got_text(&mut a2rx).await != "끊은 뒤 그룹" {}
    tick.abort();
}

/// #577 재검 7078acf0f ❌('지금 끊기' 10초 틈): 누른 뒤 폐기 전까지 옛 기기 a1 은 그룹·1:1 응용 글을 받지도 ack 하지도 않는다
/// (`hold_group_deliveries`) — relay 큐에 남은 글은 폐기 때 보낸 쪽에 `recipient_device_changed` 로 가서 새 기기가 든 뒤 다시
/// 보낸다(코어 몫은 engine 시험 16a). 전엔 a1 이 받아 '전달됨'으로 끝나 새 기기에 끝내 오지 않았다.
#[tokio::test(flavor = "multi_thread")]
async fn 지금_끊기를_누른_뒤_온_글은_옛_기기가_받지_않고_보낸_쪽이_다시_보낸다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    update_of(&mut crx, "carol", "create").await;
    // 1:1 대화도 먼저 연다(a2 가 생기기 전 — a2 잎이 없는 1:1 그룹).
    carol
        .enqueue(&Outgoing::Send {
            message: h.chat("carol@local", "alice@local", "처음"),
        })
        .unwrap();
    while got_text(&mut arx).await != "처음" {}

    // 새 기기 a2(산 기기 — 폐기 뒤 남는다). 꺼 둔 채라 아무 그룹에도 아직 잎이 없다.
    let a2k = DeviceKeys::generate(&[7; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();

    // '지금 끊기'를 눌렀다 — 폐기 전 틈에 캐럴이 그룹 글·1:1 글을 보낸다.
    alice.hold_group_deliveries(true);
    let group_msg = h.chat("carol@local", &format!("+{gid}@{SERVER}"), "끊는 중 그룹");
    let direct_msg = h.chat("carol@local", "alice@local", "끊는 중 1:1");
    let ids = [&group_msg, &direct_msg].map(|m| m["msg_id"].as_str().unwrap().to_owned());
    carol
        .enqueue(&Outgoing::Send { message: group_msg })
        .unwrap();
    carol
        .enqueue(&Outgoing::Send {
            message: direct_msg,
        })
        .unwrap();
    // 밥에게는 그룹 글이 간다 — 그때 a1 에도 deliver 됐다.
    while got_text(&mut brx).await != "끊는 중 그룹" {}
    let a1_id = ak.device_id().as_str().to_owned();
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM envelope_devices WHERE device_id = '{a1_id}' AND acked_ms IS NULL AND msg_id IN ('{}', '{}')",
            ids[0], ids[1]
        ),
        2,
    )
    .await;
    // a1 은 받지 않는다(코어에 넘기지도 ack 하지도 않음).
    let early = tokio::time::timeout(Duration::from_millis(500), async {
        loop {
            if let Some(Inbound::Deliver { .. }) = arx.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(early.is_err(), "끊는 중인 a1 이 응용 글을 받았다");
    alice.revoke_device(Duration::from_secs(10)).await.unwrap();
    let tick = ticker(&h);
    // 보낸 쪽(캐럴)에 두 글 모두 recipient_device_changed — 코어가 새 기기가 든 뒤 다시 보낸다.
    for id in &ids {
        wait(&mut crx, "recipient_device_changed", |i| {
            matches!(i, Inbound::Status { msg_id, state, fail_reason, .. }
                if msg_id == id && state == "failed" && fail_reason.as_deref() == Some("recipient_device_changed"))
        })
        .await;
    }
    tick.abort();
}

/// #577 bb2525d27 설계 리뷰 🟡: '지금 끊기'가 실패해(연결은 산 채 — LastAdmin 등) 받지 않기를 풀면, 그동안 받지 않은 글이 다음
/// 재접속까지 묶이지 않고 바로 온다(풀 때 다시 접속 — relay 는 ack 안 된 글을 접속 때만 다시 준다).
#[tokio::test(flavor = "multi_thread")]
async fn 지금_끊기가_실패해_받지_않기를_풀면_묶였던_글이_바로_온다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut crx).await;
    carol
        .enqueue(&Outgoing::Send {
            message: h.chat("carol@local", "alice@local", "처음"),
        })
        .unwrap();
    while got_text(&mut arx).await != "처음" {}

    alice.hold_group_deliveries(true);
    let held = h.chat("carol@local", "alice@local", "끊는 중");
    let id = held["msg_id"].as_str().unwrap().to_owned();
    carol.enqueue(&Outgoing::Send { message: held }).unwrap();
    let a1_id = ak.device_id().as_str().to_owned();
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM envelope_devices WHERE device_id = '{a1_id}' AND msg_id = '{id}' AND acked_ms IS NULL"
        ),
        1,
    )
    .await;
    // relay 가 a1 에 deliver 했지만 a1 은 받지 않는다.
    let early = tokio::time::timeout(Duration::from_secs(1), async {
        loop {
            if let Some(Inbound::Deliver { .. }) = arx.recv().await {
                return;
            }
        }
    })
    .await;
    assert!(early.is_err(), "끊는 중인 a1 이 응용 글을 받았다");
    // 끊기 실패 — 받지 않기를 푼다. 다시 접속해 묶였던 글을 받는다.
    alice.hold_group_deliveries(false);
    assert_eq!(got_text(&mut arx).await, "끊는 중");
}

/// 묶음 22 h4 ⓔ(§5c): 메시지가 상한을 넘는 group Handshake 는 큰 칸부터 blob 으로 — 받는 기기는 받아 해시를 맞춘 뒤 처리한다.
/// 다시 들어가기의 GroupInfo 도 blob 으로 받는다(상한을 낮춰 잎 몇 개로 잎 150 근처를 대신).
#[tokio::test(flavor = "multi_thread")]
async fn 큰_handshake_는_blob_으로_오간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start_with("alice", &ak, 1, "a.db", |c| c.mls_inline_max = 2_000);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    // Welcome·GroupInfo 가 blob 으로 갔다(relay 가 GroupInfo blob 을 붙잡아 둠).
    until_relay(&h, "SELECT COUNT(*) FROM mls_gi_blobs", 1).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "blob 뒤"),
        })
        .unwrap();
    while got_text(&mut brx).await != "blob 뒤" {}

    // bob 이 다시 들어간다 — GroupInfo 가 blob 으로 온다.
    bob.shutdown().await;
    drop(brx);
    relay_sql(
        &h,
        &format!(
            "INSERT INTO mls_rejoin (device_id, group_id, at_ms) VALUES ('{}', '{gid}', 0)",
            bk.device_id().as_str()
        ),
    );
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    update_of(&mut arx, "alice", "update").await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "다시 들어옴"),
    })
    .unwrap();
    while got_text(&mut arx).await != "다시 들어옴" {}
    tick.abort();
}

/// h4 ⓓ 리뷰 ❌: 확인 전(devcert 없음) 기기는 30분이 지나도 스스로 들어가지 않고, 나중에 devcert 를 받으면 그때부터 30분 뒤
/// 들어간다. a1 은 꺼져 있고 서명하는 a3 는 그룹 잎이 아니라(duty Add 후보 아님) 스스로 들어가기만 남는다.
#[tokio::test(flavor = "multi_thread")]
async fn 확인_전_기기는_스스로_들어가지_않고_devcert_뒤_들어간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    // a3: a1 이 서명한 확인된 기기(그룹 잎은 아님).
    let a3k = DeviceKeys::generate(&[7; 64]);
    let a3 = DeviceInfo::of("alice", None, &a3k);
    alice.plant_own_device(&a3).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &a3, true)
        .await
        .unwrap();
    let signer = format!("\"signer\":\"{}\"", ak.device_id().as_str());
    wait(
        &mut arx,
        "a3 devcert",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&signer)),
    )
    .await;
    alice.shutdown().await;
    // a3 를 먼저 띄운다 — 첫 디렉터리에 a2 가 있으면 처음 본 내 기기로 믿어 바로 서명한다.
    let (a3c, mut a3rx) = h.start_with("alice", &a3k, 7, "a3.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a3rx).await;
    // a2: 확인 전(심지 않고 등록).
    let a2k = DeviceKeys::generate(&[5; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let (_a2, mut a2rx) = h.start_with("alice", &a2k, 5, "a2.db", |c| {
        c.update_check = Duration::ZERO;
    });
    ready(&mut a2rx).await;
    let leaves = format!(
        "SELECT COUNT(*) FROM mls_leaves WHERE device_id = '{}'",
        a2k.device_id().as_str()
    );
    // 가짜 시계로 30분이 훨씬 넘게 지나도 들지 않는다.
    tokio::time::sleep(Duration::from_secs(4)).await;
    assert_eq!(relay_i64(&h, &leaves), 0);
    // a3 가 a2 를 확인(devcert) — 그 뒤 30분이면 a2 가 스스로 group 에 든다.
    a3c.trust_device("alice", a2k.device_id().as_str()).unwrap();
    // 0.2.5(g025f A): a1 이 꺼져 있어 a3 가 먼저 스스로 그룹에 들 수 있다(update 가 하나 더) — a2 가 잎이 된 뒤에 보낸다.
    until_relay(&h, &leaves, 1).await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "확인 뒤"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "확인 뒤" {}
    tick.abort();
}

/// #872: 101 의 `Lodelai-Features` 에 `own_control` 이 있으면 `Ready.own` 이 참이다 — 코어는 이것으로만 나에게서 지우기를
/// 켠다(판 숫자로 가르지 않는다).
#[tokio::test(flavor = "multi_thread")]
async fn own_control_을_알리는_relay_면_ready_own_참() {
    let h = relay().await;
    let k = h.user("alice", 1).await;
    let (_a, mut rx) = h.start("alice", &k, 1, "a.db");
    let r = wait(&mut rx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    assert!(matches!(r, Inbound::Ready { own: true, .. }), "{r:?}");
}

/// 22 §12-30 (a): 연결마다 101 의 `Lodelai-Features` 로 그룹 여부를 `Ready.groups` 에 싣는다 — 켠 relay 는 `true`, 끈 relay 는
/// `none` 이라 `false`. 끈 relay 에선 그룹 만들기 행이 시작 프레임 없이 바로 nack(unroutable)으로 빠진다(코어가 만들기 실패로
/// 끝냄, 60초 재시도 없음). 그 뒤 1:1 은 그대로 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 그룹을_끈_relay_면_ready_groups_false_만들기는_바로_실패() {
    let on = relay().await;
    let k = on.user("alice", 1).await;
    let (_a, mut rx) = on.start("alice", &k, 1, "a.db");
    let r = wait(&mut rx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    assert!(
        matches!(
            r,
            Inbound::Ready {
                groups: Some(true),
                ..
            }
        ),
        "{r:?}"
    );

    let h = relay_with(false).await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let r = wait(&mut arx, "ready", |i| matches!(i, Inbound::Ready { .. })).await;
    assert!(
        matches!(
            r,
            Inbound::Ready {
                groups: Some(false),
                ..
            }
        ),
        "{r:?}"
    );
    wait(&mut arx, "directory", |i| {
        matches!(i, Inbound::Directory(_))
    })
    .await;
    ready(&mut brx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    let change = gchange(
        &h,
        "alice@local",
        &gid,
        "create",
        &["bob@local"],
        Some("팀"),
    );
    let cid = change["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: change })
        .unwrap();
    let n = wait(
        &mut arx,
        "만들기 nack",
        |i| matches!(i, Inbound::Nack { msg_id, .. } if *msg_id == cid),
    )
    .await;
    assert!(
        matches!(&n, Inbound::Nack { reason, .. } if reason == "unroutable"),
        "{n:?}"
    );
    assert!(
        alice.group(&gid).unwrap().is_none(),
        "그룹 상태가 남지 않는다"
    );
    // 큐가 비었다 — 뒤의 1:1 이 막히지 않는다.
    let plain = h.chat("alice@local", "bob@local", "보통");
    alice
        .enqueue(&Outgoing::Send {
            message: plain.clone(),
        })
        .unwrap();
    let d = wait(&mut brx, "bob 이 1:1 받음", |i| {
        matches!(i, Inbound::Deliver { .. })
    })
    .await;
    let Inbound::Deliver { message, ack } = d else {
        unreachable!()
    };
    ack.ack();
    assert_eq!(message["msg_id"], plain["msg_id"]);
}

/// 내 다른 기기(a2)를 디렉터리로 들이고 a1 이 그 기기에 서명한 디렉터리를 읽을 때까지 — a2 의 KeyPackage 도 올라 있다.
async fn second_own_device(
    h: &Harness,
    a1: &RelayClient,
    a1k: &DeviceKeys,
) -> (DeviceKeys, RelayClient, Receiver<Inbound>) {
    let a2k = DeviceKeys::generate(&[7; 64]);
    let a2i = DeviceInfo::of("alice", None, &a2k);
    a1.plant_own_device(&a2i).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &a2i, true)
        .await
        .unwrap();
    let (a2, mut a2rx) = h.start("alice", &a2k, 7, "a2.db");
    ready(&mut a2rx).await;
    let (a1d, a2d) = (a1k.device_id(), a2k.device_id());
    let (a1d, a2d) = (a1d.as_str(), a2d.as_str());
    for i in 0..100 {
        let d = a1.directory();
        let certified = d["people"].as_array().into_iter().flatten().any(|p| {
            p["devices"].as_array().into_iter().flatten().any(|v| {
                v["device_id"] == a2d
                    && v["certs"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .any(|c| c["signer"] == a1d)
            })
        });
        if certified {
            break;
        }
        assert!(i < 99, "a1 캐시에 a2 서명이 안 보임: {d}");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    (a2k, a2, a2rx)
}

/// #490 묶음 28 §1·§2: 다른 맥의 내 세션 앞 요청은 내 다른 기기에 평소 수신으로 간다(내 기기 그룹). 처음 보내는 순간 그룹이
/// 막 시작돼 잎이 나 하나여도 Add 가 확정된 뒤에 봉인한다. 평문 머리의 처음 출처(`origin`·`origin_msg`)가 본문에 실리고, 받는
/// 기기의 상태는 원래 msg_id 로 보낸 기기에 돌아온다. 동료가 머리에 넣은 `origin:"me"` 는 버린다.
#[tokio::test(flavor = "multi_thread")]
async fn 내_다른_기기_세션_앞_요청은_출처를_싣고_상태는_원래_id_로() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (a1, mut a1rx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut a1rx).await;
    ready(&mut brx).await;
    let (_a2k, a2, mut a2rx) = second_own_device(&h, &a1, &ak).await;
    a2.enqueue(&Outgoing::Publish {
        slug: "be".into(),
        grade: "task".into(),
        liveness: "live:pty".into(),
        display: None,
        title: None,
        folder: None,
        busy: false,
        audience: None,
        project: None,
        agent: None,
        no: None,
    })
    .unwrap();
    wait(&mut a1rx, "내 세션 디렉터리", |i| {
        matches!(i, Inbound::Directory(d) if d["sessions"].as_array().is_some_and(|s| !s.is_empty()))
    })
    .await;

    let origin_msg = h.fx.ids.next_ulid();
    let mut req = h.chat("alice@local/fe", "alice@local/be", "옆 맥에 묻기");
    req["kind"] = json!("request");
    req["grade"] = json!("question");
    req["from"]["author"] = json!("agent");
    req["from"]["session_id"] = json!("cee3f37e-0000-0000-0000-000000000000");
    req["body"]["origin"] = json!("me");
    req["body"]["origin_msg"] = json!(origin_msg);
    let rid = req["msg_id"].as_str().unwrap().to_owned();
    a1.enqueue(&Outgoing::Send { message: req }).unwrap();

    let Inbound::Deliver { message, ack } = wait(
        &mut a2rx,
        "내 세션 앞 요청",
        |i| matches!(i, Inbound::Deliver { message, .. } if message["msg_id"] == rid.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    ack.ack();
    assert_eq!(message["kind"], "request");
    assert_eq!(message["from"]["address"], "alice@local/fe");
    assert_eq!(message["body"]["text"], "옆 맥에 묻기");
    assert_eq!(message["body"]["origin"], "me");
    assert_eq!(message["body"]["origin_msg"], origin_msg.as_str());

    wait(&mut a1rx, "received", |i| {
        matches!(i, Inbound::Status { msg_id, state, .. } if state == "received" && *msg_id == rid)
    })
    .await;
    a2.enqueue(&Outgoing::SenderStatus {
        msg_id: rid.clone(),
        state: lodelai_protocol::states::SenderViewState::Accepted,
        abort_reason: None,
        fail_reason: None,
    })
    .unwrap();
    wait(&mut a1rx, "accepted", |i| {
        matches!(i, Inbound::Status { msg_id, state, .. } if state == "accepted" && *msg_id == rid)
    })
    .await;

    // #967: 사진 붙인 요청도 처음 출처가 실린다 — 첨부를 올린 뒤 본문을 json1 으로 다시 만들 때 출처·멘션 칸을 버려, 받는
    // 맥이 동료 기준으로 보고 요청을 버렸다(실기에서 발견).
    let photo = h.dir.path().join("own-photo.png");
    std::fs::write(&photo, b"\x89PNG fake").unwrap();
    let mut freq = h.chat("alice@local/fe", "alice@local/be", "이 사진 봐 줘");
    freq["kind"] = json!("request");
    freq["grade"] = json!("question");
    freq["from"]["author"] = json!("agent");
    freq["from"]["session_id"] = json!("cee3f37e-0000-0000-0000-000000000000");
    freq["body"]["origin"] = json!("me");
    freq["body"]["origin_msg"] = json!(origin_msg);
    freq["body"]["mentions"] = json!(["alice@local/be"]);
    let fid = freq["msg_id"].as_str().unwrap().to_owned();
    a1.enqueue(&Outgoing::SendFiles {
        message: freq,
        attachments: vec![lodelai_relay_client::OutFile {
            path: photo,
            name: "photo.png".into(),
            mime: "image/png".into(),
            role: None,
            sha256: None,
            size_px: None,
        }],
    })
    .unwrap();
    let Inbound::Deliver { message, ack } = wait(
        &mut a2rx,
        "사진 붙인 내 세션 앞 요청",
        |i| matches!(i, Inbound::Deliver { message, .. } if message["msg_id"] == fid.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    ack.ack();
    assert_eq!(message["body"]["text"], "이 사진 봐 줘", "{message}");
    assert_eq!(
        message["body"]["files"][0]["name"], "photo.png",
        "{message}"
    );
    assert_eq!(message["body"]["origin"], "me", "{message}");
    assert_eq!(message["body"]["origin_msg"], origin_msg.as_str());
    assert_eq!(message["body"]["mentions"], json!(["alice@local/be"]));

    // 동료가 머리에 넣은 출처는 받는 내 기기에서 버린다.
    let mut peer = h.chat("bob@local", "alice@local", "나라고 해 줘");
    peer["body"]["origin"] = json!("me");
    let pid = peer["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send { message: peer }).unwrap();
    let Inbound::Deliver { message, ack } = wait(
        &mut a2rx,
        "동료 글",
        |i| matches!(i, Inbound::Deliver { message, .. } if message["msg_id"] == pid.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    ack.ack();
    assert_eq!(message["body"]["text"], "나라고 해 줘");
    assert!(message["body"].get("origin").is_none(), "{message}");
}

/// #845 §7-53: 내 기기 A 가 동료 세션에 보낸 요청의 회신은 내 기기 B 도 받는다 — B 는 A 의 요청 사본을 '내가 보낸 것'으로 적어
/// 회신의 reply_to 대조에 걸리지 않는다(전엔 unknown_delivery 로 버려 B 엔 상태만 보였다).
#[tokio::test(flavor = "multi_thread")]
async fn 내_다른_기기가_보낸_요청의_회신도_받는다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (a1, mut a1rx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut a1rx).await;
    ready(&mut brx).await;
    let (_a2k, _a2, mut a2rx) = second_own_device(&h, &a1, &ak).await;
    bob.enqueue(&Outgoing::Publish {
        slug: "be".into(),
        grade: "task".into(),
        liveness: "live:pty".into(),
        display: None,
        title: None,
        folder: None,
        busy: false,
        audience: None,
        project: None,
        agent: None,
        no: None,
    })
    .unwrap();
    wait(&mut a1rx, "bob 세션 디렉터리", |i| {
        matches!(i, Inbound::Directory(d) if d["sessions"].as_array().is_some_and(|s| !s.is_empty()))
    })
    .await;

    let mut req = h.chat("alice@local", "bob@local/be", "물어볼게");
    req["kind"] = json!("request");
    req["grade"] = json!("question");
    let rid = req["msg_id"].as_str().unwrap().to_owned();
    a1.enqueue(&Outgoing::Send { message: req }).unwrap();
    let Inbound::Deliver { ack, .. } = wait(
        &mut a2rx,
        "요청 사본",
        |i| matches!(i, Inbound::Deliver { message, .. } if message["msg_id"] == rid.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    ack.ack();
    let Inbound::Deliver { ack, .. } = wait(
        &mut brx,
        "bob 요청",
        |i| matches!(i, Inbound::Deliver { message, .. } if message["msg_id"] == rid.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    ack.ack();

    // relay 는 받아들인(accepted) 요청에만 회신을 통과시킨다(reply_accepted).
    bob.enqueue(&Outgoing::SenderStatus {
        msg_id: rid.clone(),
        state: lodelai_protocol::states::SenderViewState::Accepted,
        abort_reason: None,
        fail_reason: None,
    })
    .unwrap();
    let mut reply = h.chat("bob@local/be", "alice@local", "답이야");
    reply["kind"] = json!("reply");
    reply["reply_to"] = json!(rid);
    reply["from"]["author"] = json!("agent");
    reply["from"]["session_id"] = json!("cee3f37e-0000-0000-0000-000000000001");
    let pid = reply["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send { message: reply }).unwrap();
    let got = wait(&mut a2rx, "B 의 회신", |i| match i {
        Inbound::Deliver { message, .. } => message["msg_id"] == pid.as_str(),
        Inbound::Rejected { msg_id, .. } => *msg_id == pid,
        _ => false,
    })
    .await;
    let Inbound::Deliver { message, ack } = got else {
        panic!("B 가 회신을 버림");
    };
    ack.ack();
    assert_eq!(message["kind"], "reply");
    assert_eq!(message["body"]["text"], "답이야");
}

/// #490: 내 기기가 하나뿐일 때 내 주소로 보낸 글은 받을 잎이 없다 — relay 가 받아 두지 않고 `unroutable` 로 돌려준다(받아 두면
/// 보냈다고 보이고 아무에게도 가지 않는다). 그 뒤 생긴 내 다른 기기는 duty 로 그 내 기기 그룹에 들어간다.
#[tokio::test(flavor = "multi_thread")]
async fn 혼자인_내_기기_그룹_글은_unroutable_이고_새_기기는_뒤에_든다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let (a1, mut a1rx) = h.start("alice", &ak, 1, "a.db");
    ready(&mut a1rx).await;
    let m = h.chat("alice@local", "alice@local", "나에게");
    let id = m["msg_id"].as_str().unwrap().to_owned();
    a1.enqueue(&Outgoing::Send { message: m }).unwrap();
    let r = wait(
        &mut a1rx,
        "답",
        |i| matches!(i, Inbound::Ack { msg_id } | Inbound::Nack { msg_id, .. } if *msg_id == id),
    )
    .await;
    assert!(
        matches!(&r, Inbound::Nack { reason, .. } if reason == "unroutable"),
        "{r:?}"
    );
    assert_eq!(relay_i64(&h, "SELECT count(*) FROM envelopes"), 0);
    assert_eq!(relay_i64(&h, "SELECT count(*) FROM mls_leaves"), 1);

    let (_a2k, _a2, _a2rx) = second_own_device(&h, &a1, &ak).await;
    until_relay(&h, "SELECT count(*) FROM mls_leaves", 2).await;
}

/// g025g A7-b: 그룹이 없는 사람은 접속 때 relay 가 directory 를 쌓인 것 앞에 넣지 않는다. 앱을 새로 켜면 잎 자격 디렉터리가
/// 비어 있어, 꺼진 동안 쌓인 1:1 Welcome 이 `device_unknown` 으로 미뤄지고 뒤따른 글은 열리지 않았다. 이 접속의 디렉터리까지
/// deliver 를 잡아 두면 Welcome 으로 들고 첫 글을 연다.
#[tokio::test(flavor = "multi_thread")]
async fn 그룹_없는_사람이_앱을_새로_켜면_쌓인_1대1_첫_글을_연다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    // alice 는 KeyPackage 만 올리고 꺼진다.
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    ready(&mut arx).await;
    alice.shutdown().await;
    drop(arx);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    let first = h.chat("bob@local", "alice@local", "꺼진 동안 첫 글");
    let first_id = first["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send { message: first }).unwrap();
    until_relay(
        &h,
        &format!("SELECT COUNT(*) FROM envelopes WHERE msg_id = '{first_id}'"),
        1,
    )
    .await;
    assert_eq!(relay_i64(&h, "SELECT COUNT(*) FROM group_members"), 0);
    // 새 프로세스(같은 저장소) — 디렉터리는 비어서 시작한다.
    let (_alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    assert_eq!(got_text(&mut arx).await, "꺼진 동안 첫 글");
}

/// 시험용 TCP 중계 — 끊으면 열린 연결을 닫고 새 연결도 바로 닫는다(같은 프로세스의 클라이언트를 끊긴 채로 둔다). relay 의 Host
/// 검사(DNS rebinding)를 지나게 relay 설정 `public_host` 에 [`Gate::host`] 를 넣는다.
struct Gate {
    listener: Option<tokio::net::TcpListener>,
    addr: SocketAddr,
    up: tokio::sync::watch::Sender<bool>,
}

impl Gate {
    async fn bind() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (up, _) = tokio::sync::watch::channel(true);
        Self {
            listener: Some(listener),
            addr,
            up,
        }
    }

    fn host(&self) -> String {
        format!("127.0.0.1:{}", self.addr.port())
    }

    fn start(&mut self, to: SocketAddr) {
        let listener = self.listener.take().expect("한 번만");
        let watch = self.up.clone();
        tokio::spawn(async move {
            while let Ok((mut inc, _)) = listener.accept().await {
                let mut rx = watch.subscribe();
                if !*rx.borrow() {
                    continue;
                }
                tokio::spawn(async move {
                    let Ok(mut out) = tokio::net::TcpStream::connect(to).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inc, &mut out) => {}
                        _ = rx.wait_for(|u| !*u) => {}
                    }
                });
            }
        });
    }

    fn url(&self) -> String {
        format!("ws://{}/v1/ws", self.host())
    }

    fn set(&self, up: bool) {
        self.up.send_replace(up);
    }
}

/// 앱이 켜진 채 끊겼다 다시 붙으면 디렉터리는 지난 접속의 낡은 값이다. 그 사이 상대의 새 기기가
/// 1:1 에 들었으면 그 Add Commit 이 `device_unknown` 으로 미뤄지고, 뒤따른 상대 글은 epoch 가 어긋나 열리지 않았다. 이 접속의
/// 디렉터리까지 deliver 를 잡아 두면 Commit 을 처리하고 글을 연다.
#[tokio::test(flavor = "multi_thread")]
async fn 끊긴_사이_상대_새_기기가_든_1대1_글은_다시_붙으면_연다() {
    let mut gate = Gate::bind().await;
    let host = gate.host();
    let h = relay_cfg(true, |c| c.public_host = Some(host)).await;
    gate.start(h.addr);
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let url = gate.url();
    let (_alice, mut arx) = h.start_with("alice", &ak, 1, "a.db", |c| c.ws_url = url);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let tick = ticker(&h);
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "처음"),
    })
    .unwrap();
    assert_eq!(got_text(&mut arx).await, "처음");

    gate.set(false);
    wait(&mut arx, "끊김", |i| matches!(i, Inbound::Disconnected)).await;
    // 끊긴 동안 bob 의 새 기기가 1:1 에 든다(b1 의 duty Add) — alice 의 디렉터리에는 b2 가 없다.
    let b2k = DeviceKeys::generate(&[6; 64]);
    let b2 = DeviceInfo::of("bob", None, &b2k);
    bob.plant_own_device(&b2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &b2, true)
        .await
        .unwrap();
    let (_bob2, mut b2rx) = h.start("bob", &b2k, 6, "b2.db");
    ready(&mut b2rx).await;
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            b2k.device_id().as_str()
        ),
        1,
    )
    .await;
    let gap = h.chat("bob@local", "alice@local", "끊긴 동안");
    let gap_id = gap["msg_id"].as_str().unwrap().to_owned();
    bob.enqueue(&Outgoing::Send { message: gap }).unwrap();
    until_relay(
        &h,
        &format!("SELECT COUNT(*) FROM envelopes WHERE msg_id = '{gap_id}'"),
        1,
    )
    .await;
    gate.set(true);
    assert_eq!(got_text(&mut arx).await, "끊긴 동안");
    tick.abort();
}

/// #809·#804(0.2.6 계약 §1·§1-10): 받는 기기가 1:1 상태를 잃었다(꺼진 동안 MLS 상태를 지움 — mls_meta 는 남겨 앱도 relay 도
/// 잃은 것을 모르게, 다시 들기 표시 없음). 켜면 그 글은 `Unreadable`(ack 에 unreadable) → 그룹이 없는 대화의 글이라 스스로 다시
/// 든다 → relay 가 보낸 쪽에 received 대신 `recipient_unreadable` → 같은 msg_id 로 다시 보낸 것은 열린다(final 없음). 그 기기가
/// 보낸 글도 Sending 에서 멈추지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 받는_기기가_못_연_글은_스스로_다시_든_뒤_열린다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "첫 글"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "첫 글");
    bob.shutdown().await;
    drop(brx);
    // bob 기기의 MLS 상태를 잃음(열쇠 지문·대화 주소는 남김 — 그룹만 없어 그 1:1 글을 열 수 없다).
    {
        let c = rusqlite::Connection::open(h.dir.path().join("b.db")).unwrap();
        c.execute_batch("DELETE FROM mls_kv; DELETE FROM mls_opened;")
            .unwrap();
    }
    let m = h.chat("alice@local", "bob@local", "못 엶");
    let id = m["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::Send { message: m.clone() })
        .unwrap();
    wait(
        &mut arx,
        "ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == id),
    )
    .await;
    let (bob2, mut brx) = h.start("bob", &bk, 2, "b.db");
    let Inbound::Unreadable { message, ack } = wait(
        &mut brx,
        "못 엶",
        |i| matches!(i, Inbound::Unreadable { message, .. } if message["msg_id"] == id.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    assert_eq!(message.pointer("/body/text"), Some(&json!("")));
    ack.ack();
    // relay 는 보고를 가라앉힌 뒤(30초) tick 에 알린다.
    let tick = ticker(&h);
    // 보낸 쪽: received 가 아니라 '받는 기기가 못 엶'(n=1).
    let first = status_of(&mut arx, &id).await;
    assert_eq!(
        first,
        (
            "failed".to_owned(),
            Some("recipient_unreadable".to_owned()),
            Some("bob@local".to_owned())
        ),
    );
    // §1-10: bob 은 그룹이 없는 대화의 글을 못 열어 스스로 다시 들었다(그래서 relay 가 n=1 을 알렸다). 보낸 쪽 코어가 같은
    // msg_id 로 한 번 다시 보내면 bob 이 열고(코어가 그 행을 그 자리에서 푼다), final 은 없다.
    alice.enqueue(&Outgoing::Send { message: m }).unwrap();
    let Inbound::Deliver { message, ack } = wait(
        &mut brx,
        "다시 온 글을 엶",
        |i| matches!(i, Inbound::Deliver { message, .. } if message["msg_id"] == id.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    assert_eq!(message.pointer("/body/text"), Some(&json!("못 엶")));
    ack.ack();
    assert_eq!(
        status_of(&mut arx, &id).await.0,
        "received",
        "final 이 아니라 받음"
    );
    // bob 이 보낸 글도 멈추지 않는다(다시 든 그룹으로 봉인).
    bob2.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "bob 답"),
    })
    .unwrap();
    while got_text(&mut arx).await != "bob 답" {}
    tick.abort();
}

/// 못 엶 몰림(unreadable-backlog 판정 §2-6): 그룹 상태를 잃은 기기(bob)가 켜져 쌓인 글 여러 건을 못 연다. 그룹에 확정 전
/// Commit 이 있어 다시 들기가 물러선 동안에는 못 엶 보고가 하나도 relay 에 가지 않는다(전엔 받자마자 몰아 보고 → 보낸 기기가
/// 다시 보낸 것도 못 열어 '열지 못함'으로 굳었다). 다시 든 뒤에 새 글부터 보고가 가고, 다시 보낸 것이 모두 열리며 보낸 쪽에
/// 마지막 보고(`recipient_unreadable_final`)는 없다.
#[tokio::test(flavor = "multi_thread")]
async fn 뒤처진_기기는_다시_든_뒤에야_못_엶을_보고하고_다시_온_글을_모두_연다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let dk = h.user("dave", 4).await;
    let ek = h.user("erin", 5).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (_dave, mut drx) = h.start("dave", &dk, 4, "d.db");
    let (erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    for rx in [&mut arx, &mut brx, &mut drx, &mut erx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "erin@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx), ("erin", &mut erx)] {
        update_of(rx, who, "create").await;
    }
    update_of(&mut brx, "bob", "rename").await;
    update_of(&mut erx, "erin", "rename").await;
    // erin 은 막힌 채 붙어 있다 — alice 의 다음 Commit 이 tick 전까지 확정 전으로 남는다.
    erin.shutdown().await;
    drop(erx);
    stall(&h, "e.db", 5, &gid, true);
    let (_erin, mut erx) = h.start("erin", &ek, 5, "e.db");
    wait(&mut erx, "erin ready", |i| {
        matches!(i, Inbound::Ready { .. })
    })
    .await;
    // bob 이 꺼진 동안 그룹 상태를 잃고(그룹만 없음), 그 사이 글 넷이 쌓인다.
    bob.shutdown().await;
    drop(brx);
    {
        let c = rusqlite::Connection::open(h.dir.path().join("b.db")).unwrap();
        c.execute_batch("DELETE FROM mls_kv; DELETE FROM mls_opened;")
            .unwrap();
    }
    let mut sent = Vec::new();
    for n in 0..4 {
        let m = h.chat(
            "alice@local",
            &format!("+{gid}@{SERVER}"),
            &format!("쌓인 글 {n}"),
        );
        let id = m["msg_id"].as_str().unwrap().to_owned();
        alice
            .enqueue(&Outgoing::Send { message: m.clone() })
            .unwrap();
        wait(
            &mut arx,
            "ack",
            |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == id),
        )
        .await;
        sent.push((id, m));
    }
    // 확정 전 Commit(dave 더하기) — bob 의 external commit 이 stale_epoch 로 물러선다.
    let mut add = gchange(&h, "alice@local", &gid, "add", &[], None);
    add["subject"] = json!("dave@local");
    add["body"] =
        json!({"enc": "plain", "text": json!({"op": "add", "subject": "dave@local"}).to_string()});
    let add_id = add["msg_id"].as_str().unwrap().to_owned();
    alice
        .enqueue(&Outgoing::GroupChange { message: add })
        .unwrap();
    wait(
        &mut arx,
        "add ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == add_id),
    )
    .await;
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    // 넷 다 못 연다 — 코어가 저장하고 ack(= 못 엶 보고)까지 한다.
    for _ in 0..sent.len() {
        let Inbound::Unreadable { message, ack } = wait(&mut brx, "못 엶", |i| {
            matches!(i, Inbound::Unreadable { message, .. }
                if sent.iter().any(|(id, _)| message["msg_id"] == id.as_str()))
        })
        .await
        else {
            unreachable!()
        };
        assert_eq!(message.pointer("/body/text"), Some(&json!("")));
        ack.ack();
    }
    // 다시 들기 전(확정 전 Commit 때문에 물러선 동안): 보고 0. 흘리는 갈래(250ms)가 여러 번 돌 만큼 기다려 본다.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM mls_pending"),
        1,
        "아직 확정 전"
    );
    assert_eq!(
        relay_i64(&h, "SELECT COUNT(*) FROM unreadable_reports"),
        0,
        "다시 들기 전에 못 엶을 보고했다"
    );
    // 확정 → 다시 듦 → 보고가 흐른다(새 글부터) → 보낸 쪽에 '받는 기기가 못 엶'(n=1).
    let tick = ticker(&h);
    until_relay(&h, "SELECT COUNT(*) FROM unreadable_reports", 4).await;
    let first: String = {
        let c = rusqlite::Connection::open(h.dir.path().join("relay.db")).unwrap();
        c.busy_timeout(Duration::from_secs(5)).unwrap();
        c.query_row(
            "SELECT msg_id FROM unreadable_reports ORDER BY rowid LIMIT 1",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(first, sent[3].0, "새 글부터 보고한다");
    let mut told = std::collections::HashSet::new();
    while told.len() < sent.len() {
        let Inbound::Status {
            msg_id,
            state,
            fail_reason,
            ..
        } = wait(&mut arx, "못 엶 알림", |i| {
            matches!(i, Inbound::Status { msg_id, fail_reason: Some(_), .. }
                if sent.iter().any(|(id, _)| id == msg_id))
        })
        .await
        else {
            unreachable!()
        };
        assert_eq!(
            (state.as_str(), fail_reason.as_deref()),
            ("failed", Some("recipient_unreadable")),
            "{msg_id}"
        );
        told.insert(msg_id);
    }
    // 보낸 쪽 코어가 하듯 같은 msg_id 로 한 번씩 다시 보낸다 — 다시 든 bob 이 모두 연다.
    for (_, m) in &sent {
        alice
            .enqueue(&Outgoing::Send { message: m.clone() })
            .unwrap();
    }
    let mut opened = std::collections::HashSet::new();
    while opened.len() < sent.len() {
        let Inbound::Deliver { message, ack } = wait(&mut brx, "다시 온 글을 엶", |i| {
            matches!(i, Inbound::Deliver { message, .. }
                if sent.iter().any(|(id, _)| message["msg_id"] == id.as_str()))
        })
        .await
        else {
            unreachable!()
        };
        let text = message
            .pointer("/body/text")
            .and_then(Value::as_str)
            .unwrap();
        assert!(text.starts_with("쌓인 글 "), "{text}");
        opened.insert(message["msg_id"].as_str().unwrap().to_owned());
        ack.ack();
    }
    until_relay(
        &h,
        "SELECT COUNT(*) FROM unreadable_reports WHERE opened = 1",
        4,
    )
    .await;
    // 마지막 보고('열지 못함')는 없다.
    tokio::time::sleep(Duration::from_millis(500)).await;
    while let Ok(i) = arx.try_recv() {
        if let Inbound::Status { fail_reason, .. } = &i {
            assert_ne!(
                fail_reason.as_deref(),
                Some("recipient_unreadable_final"),
                "다시 보낸 것이 열렸는데 '열지 못함'"
            );
        }
    }
    tick.abort();
}

/// 못 엶 몰림(unreadable-backlog 판정 §2-3): 다시 들기가 그만두면(relay 에 그 대화의 GroupInfo 가 없다) 쥐고 있던 못 엶
/// 보고를 그때 낸다 — 쥔 채 조용히 남지 않는다(보낸 쪽이 만료까지 '보냄'에 머물지 않게).
#[tokio::test(flavor = "multi_thread")]
async fn 다시_들기가_그만두면_쥐고_있던_못_엶_보고를_낸다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "첫 글"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "첫 글");
    bob.shutdown().await;
    drop(brx);
    {
        let c = rusqlite::Connection::open(h.dir.path().join("b.db")).unwrap();
        c.execute_batch("DELETE FROM mls_kv; DELETE FROM mls_opened;")
            .unwrap();
    }
    let m = h.chat("alice@local", "bob@local", "못 엶");
    let id = m["msg_id"].as_str().unwrap().to_owned();
    alice.enqueue(&Outgoing::Send { message: m }).unwrap();
    wait(
        &mut arx,
        "ack",
        |i| matches!(i, Inbound::Ack { msg_id } if *msg_id == id),
    )
    .await;
    // relay 에서 그 대화의 그룹이 사라졌다 — bob 의 다시 들기는 GroupInfo 를 못 받아 그만둔다.
    relay_sql(&h, "DELETE FROM mls_groups");
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let Inbound::Unreadable { ack, .. } = wait(
        &mut brx,
        "못 엶",
        |i| matches!(i, Inbound::Unreadable { message, .. } if message["msg_id"] == id.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    ack.ack();
    until_relay(
        &h,
        &format!("SELECT COUNT(*) FROM unreadable_reports WHERE msg_id = '{id}'"),
        1,
    )
    .await;
}

/// §1-10 ③: 1:1 상태를 잃은 기기(mls_meta 남김·다시 들기 표시 없음)가 상대 글 없이 먼저 보낸다 — 시작이 epoch_taken 으로 거절되면
/// 전에 쓰던 대화라 Welcome 을 기다리지 않고 스스로 다시 든 뒤 보낸다(Sending 에 멈추지 않음, 60초 기다림 없음).
#[tokio::test(flavor = "multi_thread")]
async fn 상태_잃은_기기가_먼저_보내면_다시_든_뒤_간다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "첫 글"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "첫 글");
    bob.shutdown().await;
    drop(brx);
    {
        let c = rusqlite::Connection::open(h.dir.path().join("b.db")).unwrap();
        c.execute_batch("DELETE FROM mls_kv; DELETE FROM mls_opened;")
            .unwrap();
    }
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    // relay tick(실제 relay 는 30초마다) — 다시 들기 확정·창 끝 판정.
    let tick = ticker(&h);
    let t0 = std::time::Instant::now();
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "먼저 보냄"),
    })
    .unwrap();
    while got_text(&mut arx).await != "먼저 보냄" {}
    assert!(
        t0.elapsed() < Duration::from_secs(30),
        "Welcome 60초를 기다리지 않음 — {:?}",
        t0.elapsed()
    );
    // 다시 든 뒤 alice 의 글도 bob 이 연다.
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "다시 든 뒤"),
        })
        .unwrap();
    while got_text(&mut brx).await != "다시 든 뒤" {}
    tick.abort();
}

/// 그 글의 다음 status (state, fail_reason, by) — received·read·failed·expired 중 먼저 온 것.
async fn status_of(
    rx: &mut Receiver<Inbound>,
    id: &str,
) -> (String, Option<String>, Option<String>) {
    let Inbound::Status {
        state,
        fail_reason,
        by,
        ..
    } = wait(
        rx,
        "status",
        |i| matches!(i, Inbound::Status { msg_id, .. } if msg_id == id),
    )
    .await
    else {
        unreachable!()
    };
    (state, fail_reason, by)
}

/// #819(설계 🟡): 깨짐 무효 셈은 그 그룹 응용 글이 열려도 지우지 않는다 — 무효 고리에선 epoch 가 그대로라 깨진 잎도 글은
/// 열 수 있어, 글로 지우면 활발한 그룹에서 셈이 늘 0 이 되어 영영 다시 들지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 그룹_글을_열어도_깨짐_무효_셈은_남는다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    for rx in [&mut arx, &mut brx] {
        ready(rx).await;
    }
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    for (who, rx) in [("alice", &mut arx), ("bob", &mut brx)] {
        update_of(rx, who, "create").await;
    }
    bob.shutdown().await;
    drop(brx);
    let bdb = h.dir.path().join("b.db");
    MlsStore::open(&bdb, &store_key(2), Arc::new(OsRng))
        .unwrap()
        .note_broken_void(gid.as_bytes(), "dev-x")
        .unwrap();
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", &format!("+{gid}@{SERVER}"), "열리는 글"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "열리는 글");
    bob.shutdown().await;
    let (n, _) = MlsStore::open(&bdb, &store_key(2), Arc::new(OsRng))
        .unwrap()
        .note_broken_void(gid.as_bytes(), "dev-x")
        .unwrap();
    assert_eq!(n, 2, "글을 열어도 셈은 남는다");
}

/// #595: 옛 기기 a1 이 끊기고 새 기기 a2 만 남았는데 남은 멤버 하나(carol)가 꺼져 있으면, bob 의 a1 Remove 는 창 끝에야 확정된다.
/// 그 사이 a2 의 external commit 은 트리의 a1 때문에 물러섬이 길어지고, a2 는 잎이 아니라 확정을 모른다 — relay 가 확정 뒤 다시
/// 들기 신호를 다시 보내 물러섬 끝(최대 60초)을 기다리지 않고 바로 든다.
#[tokio::test(flavor = "multi_thread")]
async fn 남은_멤버가_꺼져_있어도_옛_잎이_빠지면_새_기기가_물러섬_없이_든다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    let (_carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut crx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    // 그룹 {alice, bob} — 끊긴 a1 잎이 GroupInfo 에 남는 경우(리뷰 🔴, 백엔드 재현 6490603738 ③).
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    update_of(&mut crx, "carol", "create").await;
    // carol 은 붙은 채 표를 내지 않게 다시 켠다 — bob 의 a1 Remove 가 확정 전으로 남는다(연결된 투표자가 없으면 배달 직후
    // 확정이라 — #846). carol 이 꺼지는 tick 에 확정.
    _carol.shutdown().await;
    drop(crx);
    let (carol, mut crx) = h.start_with("carol", &ck, 3, "c.db", |c| c.hold_commit_ack = true);
    ready(&mut crx).await;

    // a2: 같은 계정의 새 기기 — 옛 기기가 확인하지 않았다(pending).
    let a2k = DeviceKeys::generate(&[6; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 6, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    a2c.recover(
        lodelai_relay_client::Recover::Start,
        Duration::from_secs(10),
    )
    .await
    .unwrap();
    // 옛 기기 a1 에 막기 카드 재료가 온다.
    wait(&mut arx, "recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 시험 19: 앱을 다시 켜도(인증 직후) 막기 카드 재료가 다시 온다 — 코어는 저장하지 않는다.
    alice.shutdown().await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut arx, "다시 켠 뒤 recover_against", |i| {
        matches!(i, Inbound::RecoverAgainst { requester, .. } if requester == a2k.device_id().as_str())
    })
    .await;
    // 막지 않고 24h — 옛 기기가 걸기 동안 붙어 있었으니 relay 가 한 번 미루고(#737), 그 24h 뒤 끊는다(by recovery).
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    h.fx.clock.advance(25 * 3_600_000);
    h.app.expire_tick();
    let revoked = |i: &Inbound| {
        matches!(
            i,
            Inbound::RemovedFromAccount {
                by: lodelai_relay_client::RemovedBy::Recovery,
                at: Some(_)
            }
        )
    };
    wait(&mut arx, "끊김", revoked).await;
    alice.shutdown().await;
    // 끊긴 옛 기기는 다시 켜도 같은 사유로(시험 19·22 — 앱은 지우지 않고 사유를 보인다).
    let (_old, mut orx) = h.start("alice", &ak, 1, "a.db");
    wait(&mut orx, "다시 켠 뒤 끊김", revoked).await;
    // a2 는 1:1 에는 바로 든다(bob 이 접속해 ack).
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'pair' AND l.device_id = '{}'",
            a2k.device_id().as_str()
        ),
        1,
    )
    .await;
    // 그룹은 트리에 끊긴 a1 이 남아 external commit 을 못 만든다 — 물러섬이 2·4·8 로 길어지게 둔다(다음 시도는 30초 무렵).
    tokio::time::sleep(Duration::from_secs(15)).await;
    let a2_group = format!(
        "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group' AND l.device_id = '{}'",
        a2k.device_id().as_str()
    );
    assert_eq!(relay_i64(&h, &a2_group), 0, "아직 그룹 잎 아님");
    // carol 이 꺼진 뒤 tick 한 번 — 연결된 투표자가 없어 a1 Remove 확정. relay 가 다시 들기 신호를 다시 보내 a2 는 물러섬 끝을
    // 기다리지 않고 든다(#595).
    carol.shutdown().await;
    drop(crx);
    for _ in 0..50 {
        h.app.expire_tick();
        if relay_i64(&h, "SELECT COUNT(*) FROM mls_pending") == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    until_relay(&h, &a2_group, 1).await;
    // bob 이 a2 의 들기(external commit, actor alice)를 반영한 뒤 보낸다 — 앞 epoch 로 나간 글은 a2 가 못 읽는다. a1 을 뺀
    // update(actor 는 의무를 맡은 bob·carol)도 같은 op·seq 로 먼저 쌓여 있을 수 있어 actor 로 가른다(전체 검사 때 그걸 집어 간헐 실패).
    wait(&mut brx, "bob 이 a2 들기 반영", |i| {
        matches!(i, Inbound::GroupUpdate { op, actor, .. } if op == "update" && actor == "alice@local")
    })
    .await;
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", &format!("+{gid}@{SERVER}"), "확정 뒤 그룹"),
    })
    .unwrap();
    while got_text(&mut a2rx).await != "확정 뒤 그룹" {}
    drop(a2c);
}

/// #836: 이름을 다시 보낼 옛 잎은 새로 든 기기와 같은 사용자(곧 끊길 옛 기기일 수 있다)가 아니라 다른 사용자의 기기에서 고른다.
/// 경주를 굳힌 꼴('지금 끊기'에서 a1 이 확정 직후 폐기되는 것과 같은 결과): bob·carol 이 꺼진 동안 a1 이 a2 Add 를 내고 바로
/// 꺼진다 → 돌아온 bob·carol 의 ack 로 확정, a1 은 그 확정을 못 받는다. 전엔 가장 작은 옛 잎 a1 이 맡아 아무도 이름을 다시
/// 보내지 않았다.
#[tokio::test(flavor = "multi_thread")]
async fn 옛_기기가_확정을_못_받아도_새_기기는_그룹_이름을_안다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let ck = h.user("carol", 3).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, mut crx) = h.start("carol", &ck, 3, "c.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    ready(&mut crx).await;
    let gid = h.fx.ids.next_ulid().to_lowercase();
    alice
        .enqueue(&Outgoing::GroupChange {
            message: gchange(
                &h,
                "alice@local",
                &gid,
                "create",
                &["bob@local", "carol@local"],
                Some("팀"),
            ),
        })
        .unwrap();
    update_of(&mut brx, "bob", "create").await;
    update_of(&mut crx, "carol", "create").await;
    bob.shutdown().await;
    carol.shutdown().await;
    drop((brx, crx));
    // bob 은 붙은 채 표를 내지 않게 다시 켠다 — 연결된 투표자가 없으면 a2 Add 가 배달 직후 확정돼 a1 이 확정을 받는다(#846).
    let (bob, mut brx) = h.start_with("bob", &bk, 2, "b.db", |c| c.hold_commit_ack = true);
    ready(&mut brx).await;

    let a2k = DeviceKeys::generate(&[7; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &a2k),
        true,
    )
    .await
    .unwrap();
    let a2_id = a2k.device_id().as_str().to_owned();
    // a2 를 켜 KeyPackage 를 올린다(a1 의 Add 재료).
    let (a2c, mut a2rx) = h.start_with("alice", &a2k, 7, "a2.db", |c| {
        c.orphan_wait = Duration::from_secs(365 * 86_400);
        c.update_check = Duration::from_secs(365 * 86_400);
    });
    ready(&mut a2rx).await;
    // a1 이 a2 를 서명 → add_device 로 a2 Add 를 낸다(투표자 bob 이 표를 내지 않아 확정 전으로 남음) → a1 은 꺼진다.
    // a1 이 디렉터리에서 a2 를 볼 때까지(최대 10초).
    let mut trusted = false;
    for _ in 0..100 {
        if alice.trust_device("alice", &a2_id).is_ok() {
            trusted = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(trusted, "a1 이 a2 를 서명");
    until_relay(
        &h,
        "SELECT COUNT(*) FROM mls_pending p JOIN mls_groups g ON g.group_id = p.group_id WHERE g.kind = 'group'",
        1,
    )
    .await;
    alice.shutdown().await;
    drop(arx);
    // bob 은 보통으로 다시, carol 이 돌아와 ack → 창 끝 확정(a1 은 꺼져 확정을 못 받는다).
    bob.shutdown().await;
    drop(brx);
    let (_bob, _brx) = h.start("bob", &bk, 2, "b.db");
    let (carol, _crx) = h.start("carol", &ck, 3, "c.db");
    let tick = ticker(&h);
    until_relay(
        &h,
        &format!(
            "SELECT COUNT(*) FROM mls_leaves l JOIN mls_groups g ON g.group_id = l.group_id WHERE g.kind = 'group' AND l.device_id = '{a2_id}'"
        ),
        1,
    )
    .await;
    let mut name = String::new();
    for _ in 0..100 {
        name = a2c.group(&gid).unwrap().map(|g| g.name).unwrap_or_default();
        if name == "팀" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(name, "팀", "다른 사용자의 옛 잎이 이름을 다시 보낸다");
    carol
        .enqueue(&Outgoing::Send {
            message: h.chat("carol@local", &format!("+{gid}@{SERVER}"), "확정 뒤 그룹"),
        })
        .unwrap();
    while got_text(&mut a2rx).await != "확정 뒤 그룹" {}
    tick.abort();
}

fn relay_text(h: &Harness, sql: &str) -> Option<String> {
    let c = rusqlite::Connection::open(h.dir.path().join("relay.db")).unwrap();
    c.busy_timeout(Duration::from_secs(5)).unwrap();
    c.query_row(sql, [], |r| r.get::<_, Option<String>>(0))
        .ok()
        .flatten()
}

/// 모바일 검증 S2: 접속 안 한 bob 앞으로 보관된 1:1 응용 메시지를 relay 와 같은 봉인(push::seal)으로 싸서 알림 쪽(open_push)이
/// relay 연결 없이 연다. 연 평문은 mls_opened 에 남아, bob 이 다시 붙어 그 글을 받을 때 다시 풀지 않고(이미 키를 썼다) 그것으로
/// 연다. 키가 다르면 push key mismatch.
async fn push_open_then_app(tamper: Option<&str>) {
    use lodelai_relay_client::push_open::{open_push, OpenError};
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");
    bob.shutdown().await;

    let msg = h.chat("alice@local", "bob@local", "알림 글");
    let msg_id = msg["msg_id"].as_str().unwrap().to_owned();
    alice.enqueue(&Outgoing::Send { message: msg }).unwrap();
    let sql = format!("SELECT message FROM envelopes WHERE msg_id = '{msg_id}'");
    let mut stored = None;
    for _ in 0..100 {
        stored = relay_text(&h, &sql);
        if stored.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stored: Value = serde_json::from_str(&stored.expect("relay 에 보관")).unwrap();
    let mls_bytes = lodelai_crypto::encoding::decode(
        stored
            .pointer("/body/payload/data")
            .and_then(Value::as_str)
            .unwrap(),
        "mls",
    )
    .unwrap();
    let key = [7u8; 32];
    let p = lodelai_relay::push::seal(&key, [3; 12], &msg_id, &mls_bytes).unwrap();
    let db = h.dir.path().join("b.db");
    let now = lodelai_effects::SystemClock.now().0 as u64 / 1000;

    assert_eq!(
        open_push(&db, &store_key(2), &[8u8; 32], &p, now, SERVER),
        Err(OpenError::KeyMismatch)
    );
    let opened = open_push(&db, &store_key(2), &key, &p, now, SERVER).unwrap();
    assert_eq!(opened.msg_id, msg_id);
    assert_eq!(opened.sender, ak.device_id().as_str());
    assert_eq!(
        (
            opened.body.as_str(),
            opened.sender_user.as_str(),
            opened.has_files
        ),
        ("알림 글", "alice", false)
    );
    assert_eq!(
        opened.conversation.as_deref(),
        Some("alice@local"),
        "화면이 여는 대화"
    );
    // 같은 알림이 또 와도(키는 이미 썼다) 남긴 평문으로.
    assert_eq!(
        open_push(&db, &store_key(2), &key, &p, now, SERVER).unwrap(),
        opened
    );

    if let Some(set) = tamper {
        // 알림으로 연 글의 보낸 기기가 봉투와 다르다(§12-11 ⓔ)·다른 대화(그룹)의 글이다(relay 가 정한 msg_id 로 옮겨 붙임)
        // — 앱은 그 글을 내지 않는다.
        let c = rusqlite::Connection::open(&db).unwrap();
        c.execute(
            &format!("UPDATE mls_opened SET {set} WHERE msg_id = ?1"),
            [&msg_id],
        )
        .unwrap();
    }
    // 앱이 다시 붙어 그 글을 받는다 — 다시 풀면 실패할 글을 mls_opened 로 연다.
    let (_bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "다음"),
        })
        .unwrap();
    // 끄기 전 ack 가 안 닿은 앞 글이 다시 올 수 있다 — '다음' 까지 받은 글을 모은다.
    let mut got = Vec::new();
    loop {
        let t = got_text(&mut brx).await;
        if t == "다음" {
            break;
        }
        got.push(t);
    }
    assert_eq!(
        got.iter().any(|t| t == "알림 글"),
        tamper.is_none(),
        "{got:?}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn 알림으로_연_1대1_글을_앱이_다시_풀지_않고_연다() {
    push_open_then_app(None).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn 알림으로_연_글의_보낸_기기가_봉투와_다르면_앱이_버린다() {
    push_open_then_app(Some("sender = 'k1_BBBBBBBBBBBBBBBBBBBBBB'")).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn 알림으로_연_글이_다른_대화의_것이면_앱이_버린다() {
    push_open_then_app(Some("gid = x'00112233'")).await;
}

/// #839: 새 기기가 1:1 을 처음 시작하려고 KeyPackage 를 가져오는 사이에 그 1:1 의 Welcome(내 다른 기기의 duty Add)이 들어와
/// 그룹이 생겨도, 시작 실패로 60초 물러서지 않고 그 그룹으로 바로 보낸다. relay 시험 손잡이로 b2 의 claim 답만 쥐어 그 창을
/// 결정적으로 만든다(시간이 아니라 Notify 로 푼다).
#[tokio::test(flavor = "multi_thread")]
async fn 새_기기_첫_1대1_은_claim_중_welcome_이_와도_물러서지_않는다() {
    let b2k = DeviceKeys::generate(&[6; 64]);
    let hold = lodelai_relay::ClaimHold::new(b2k.device_id().as_str());
    let h = relay_cfg(true, |c| c.claim_hold = Some(hold.clone())).await;
    let ak = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut arx).await;
    ready(&mut brx).await;
    alice
        .enqueue(&Outgoing::Send {
            message: h.chat("alice@local", "bob@local", "처음"),
        })
        .unwrap();
    assert_eq!(got_text(&mut brx).await, "처음");

    // b2 가 claim 하기 전에 아무도 b2 를 1:1 에 넣지 못하게 둘 다 꺼 둔다.
    let b2 = DeviceInfo::of("bob", None, &b2k);
    bob.plant_own_device(&b2).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &b2, true)
        .await
        .unwrap();
    // #888: 확인 전 기기는 큐를 멈추고 relay 도 claim 을 받지 않는다 — bob1 이 b2 devcert 를 올린 뒤 끈다. b2 는 아직 KeyPackage
    // 를 안 올려 bob1 이 지금 Add 할 수 없다(duty 만 남는다).
    let signer = format!("\"signer\":\"{}\"", bk.device_id().as_str());
    wait(
        &mut brx,
        "b2 devcert",
        |i| matches!(i, Inbound::Directory(d) if d.to_string().contains(&signer)),
    )
    .await;
    alice.shutdown().await;
    bob.shutdown().await;
    // 큐 차례(pace)를 길게 — Welcome 과 claim 답이 차례 사이 한 틈에 처리된다(실제 부하에서 일어난 순서). 짧으면 Welcome 뒤
    // 차례가 먼저 돌아 그룹으로 보내 버려 창을 지나지 않는다.
    let (bob2, mut b2rx) = h.start_with("bob", &b2k, 6, "b2.db", |c| {
        c.send_interval = Duration::from_secs(6);
    });
    ready(&mut b2rx).await;
    bob2.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "새 기기에서"),
    })
    .unwrap();
    // b2 의 claim 이 relay 에서 쥐였다 — 이제 bob1 이 붙어 duty 로 b2 를 1:1 에 넣고, Welcome 이 b2 에 간다.
    tokio::time::timeout(Duration::from_secs(20), hold.reached.notified())
        .await
        .expect("b2 가 1:1 시작 claim 을 보냄");
    let (_bob, _brx) = h.start("bob", &bk, 2, "b.db");
    let (_alice, mut arx) = h.start("alice", &ak, 1, "a.db");
    ready(&mut arx).await;
    let leaves = format!(
        "SELECT COUNT(*) FROM mls_leaves WHERE device_id = '{}'",
        b2k.device_id().as_str()
    );
    until_relay(&h, &leaves, 1).await;
    // relay 가 확정 뒤 Welcome 을 b2 에 보냈다 — b2 가 그 1:1 에 든 것을 본 뒤 claim 답을 푼다(상한 5초).
    let mut joined = false;
    for _ in 0..100 {
        if bob2.has_pair_group("alice") {
            joined = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(joined, "5초 안에 b2 가 Welcome 으로 1:1 에 들지 않음");
    hold.release.notify_one();
    // 고치기 전: 시작 실패 → 60초 물러섬. 고친 뒤: 그 그룹으로 다음 차례에. 차례 간격이 6초라 풀린 뒤 받기까지는 차례
    // 하나(실측 5.8~5.9초, #970 25판)이고, 차례 하나를 놓치면 ~12초(재현은 안 됨). 상한은 60초 물러섬과 가르기만 하면
    // 되므로 차례 셋 남짓으로 둔다(10초는 차례 둘보다 짧아 부하에서 간헐 실패했다).
    let got = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            if got_text(&mut arx).await == "새 기기에서" {
                break;
            }
        }
    })
    .await;
    assert!(got.is_ok(), "20초 안에 받지 못함(시작 실패 물러섬)");
}

/// 11-06 설계 덧: 확인 전 내 기기를 빼면(다른 내 기기가 없으면) 기다림 칸이 없어지고 곧 끝난다 — 물러섬 상한까지
/// 기다리지 않는다. 받을 기기가 없으니 끝은 #490 과 같은 unroutable.
#[tokio::test(flavor = "multi_thread")]
async fn 확인_전_내_기기를_빼면_내_기기_대화_첫_글이_곧_끝난다() {
    let h = relay().await;
    let k1 = h.user("alice", 1).await;
    h.fx.clock.advance(1000);
    let k2 = DeviceKeys::generate(&[3; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &k2),
        true,
    )
    .await
    .unwrap();
    let (a1, mut rx1) = h.start("alice", &k1, 1, "a1.db");
    ready(&mut rx1).await;
    let id2 = k2.device_id().as_str().to_owned();
    until_peer(&a1, &id2).await;
    let msg = h.chat("alice@local", "alice@local", "혼자라도");
    let msg_id = msg["msg_id"].as_str().unwrap().to_owned();
    a1.enqueue(&Outgoing::Send { message: msg }).unwrap();
    let wait_of = || a1.send_waits().into_iter().find(|w| w.msg_id == msg_id);
    let mut seen = None;
    for _ in 0..50 {
        seen = wait_of();
        if seen.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        seen.map(|w| w.reason),
        Some(SendWaitReason::OwnDeviceUnconfirmed)
    );
    // 물러섬이 길어진 뒤(2·4초 다음은 8초) 뺀다.
    tokio::time::sleep(Duration::from_millis(6500)).await;
    a1.revoke_other_device(&id2, Duration::from_secs(3))
        .await
        .unwrap();
    // 받을 내 기기가 없으니 끝은 #490 과 같은 unroutable 이다(11-07 설계 다시 판정). 물러섬 상한을 기다리지 않는다.
    let done = tokio::time::timeout(
        Duration::from_secs(4),
        wait(&mut rx1, "끝남", |i| {
            matches!(i, Inbound::Ack { msg_id: m } | Inbound::Nack { msg_id: m, .. } if *m == msg_id)
        }),
    )
    .await
    .expect("빼고 4초 안에 끝나지 않음");
    assert!(
        matches!(&done, Inbound::Nack { reason, .. } if reason == "unroutable"),
        "{done:?}"
    );
    assert!(wait_of().is_none(), "칸이 남음: {:?}", wait_of());
}

/// 알림시험 흔들림 (a): 내 다른 기기가 디렉터리에 있는데 아직 잎 자격이 없으면(확인 전·방금 확인) 내 기기 대화의 첫 글은 혼자
/// 시작해 relay `unroutable`(받을 잎 없음)로 버려지지 않는다 — 만료까지 기다리다 그 기기의 잎 자격이 생기면 바로 그 기기에 간다.
#[tokio::test(flavor = "multi_thread")]
async fn 확인_전_내_기기가_있으면_내_기기_대화_첫_글은_기다렸다_간다() {
    let h = relay().await;
    let k1 = h.user("alice", 1).await;
    h.fx.clock.advance(1000);
    // 내 새 기기 — 심지 않고 등록(확인 전, 잎 자격 없음).
    let k2 = DeviceKeys::generate(&[3; 64]);
    lodelai_relay_client::register::register_device_with(
        h.addr,
        TOKEN,
        &DeviceInfo::of("alice", None, &k2),
        true,
    )
    .await
    .unwrap();
    let (a1, mut rx1) = h.start("alice", &k1, 1, "a1.db");
    let (_a2, mut rx2) = h.start("alice", &k2, 3, "a2.db");
    ready(&mut rx1).await;
    ready(&mut rx2).await;
    let id2 = k2.device_id().as_str().to_owned();
    until_peer(&a1, &id2).await;
    assert_eq!(
        a1.store().peer(&id2).unwrap().unwrap().trust,
        lodelai_relay_client::Trust::Pending
    );
    let msg = h.chat("alice@local", "alice@local", "내 기기에");
    let msg_id = msg["msg_id"].as_str().unwrap().to_owned();
    a1.enqueue(&Outgoing::Send { message: msg }).unwrap();
    // 기다리는 동안 실패(nack)로 끝내지 않는다.
    let early = tokio::time::timeout(
        Duration::from_millis(1500),
        wait(&mut rx1, "nack", |i| matches!(i, Inbound::Nack { .. })),
    )
    .await;
    assert!(early.is_err(), "기다리지 않고 실패: {early:?}");
    // 화면 칸(11-06): 확인 전 그 내 기기를 기다린다고 알린다.
    let wait_of = || a1.send_waits().into_iter().find(|w| w.msg_id == msg_id);
    let mut seen = None;
    for _ in 0..50 {
        seen = wait_of();
        if seen.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let seen = seen.expect("기다림 까닭이 없음");
    assert_eq!(
        seen.reason,
        SendWaitReason::OwnDeviceUnconfirmed,
        "{seen:?}"
    );
    assert_eq!(seen.device.as_deref(), Some(id2.as_str()));
    a1.trust_device("alice", &id2).unwrap();
    assert_eq!(got_text(&mut rx2).await, "내 기기에");
    // 확인한 뒤로는 '확인 전'이 아니다(나갔으면 칸 없음, 아직이면 준비 기다림).
    if let Some(w) = wait_of() {
        assert_eq!(w.reason, SendWaitReason::OwnDeviceNotReady, "{w:?}");
        assert_eq!(w.device.as_deref(), Some(id2.as_str()));
    }
}

/// #870 own_stream: 내 두 기기가 self 그룹 exporter 키로 흘림을 주고받는다(relay 는 속을 모르고 붙은 기기에만 넘김). 보내는
/// 쪽을 같은 epoch 에서 다시 켜도(가짜 시계라 시각이 그대로) keyframe 때 남긴 seq 위에서 이어 가 받는 쪽 재생 창에 막히지 않는다.
#[tokio::test(flavor = "multi_thread")]
async fn 내_기기끼리_흘림이_오가고_보내는_쪽을_다시_켜도_이어진다() {
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let (a1, mut a1rx) = h.start("alice", &ak, 1, "a.db");
    ready(&mut a1rx).await;
    let (a2k, a2, mut a2rx) = second_own_device(&h, &a1, &ak).await;
    // self 그룹 세우기 — a2 의 세션 앞 요청을 a1 이 보낸다(처음 보내는 순간 a1 이 그룹을 만들고 a2 를 넣는다).
    a2.enqueue(&Outgoing::Publish {
        slug: "be".into(),
        grade: "task".into(),
        liveness: "live:pty".into(),
        display: None,
        title: None,
        folder: None,
        busy: false,
        audience: None,
        project: None,
        agent: None,
        no: None,
    })
    .unwrap();
    wait(&mut a1rx, "내 세션 디렉터리", |i| {
        matches!(i, Inbound::Directory(d) if d["sessions"].as_array().is_some_and(|s| !s.is_empty()))
    })
    .await;
    let mut req = h.chat("alice@local/fe", "alice@local/be", "그룹 세우기");
    req["kind"] = json!("request");
    req["grade"] = json!("question");
    req["from"]["author"] = json!("agent");
    req["from"]["session_id"] = json!("cee3f37e-0000-0000-0000-000000000000");
    let rid = req["msg_id"].as_str().unwrap().to_owned();
    a1.enqueue(&Outgoing::Send { message: req }).unwrap();
    let Inbound::Deliver { ack, .. } = wait(
        &mut a2rx,
        "내 세션 앞 요청",
        |i| matches!(i, Inbound::Deliver { message, .. } if message["msg_id"] == rid.as_str()),
    )
    .await
    else {
        unreachable!()
    };
    ack.ack();

    let (d1, d2) = (
        ak.device_id().as_str().to_owned(),
        a2k.device_id().as_str().to_owned(),
    );
    let got = |from: &str, text: &'static [u8]| {
        let from = from.to_owned();
        move |i: &Inbound| matches!(i, Inbound::OwnStream { from_device, data } if *from_device == from && data == text)
    };
    a1.own_stream(&d2, b"state".to_vec(), false);
    wait(&mut a2rx, "a1 → a2 흘림", got(&d1, b"state")).await;
    // keyframe 때 seq 를 남긴다.
    a2.own_stream(&d1, b"key".to_vec(), true);
    wait(&mut a1rx, "a2 → a1 흘림", got(&d2, b"key")).await;
    a2.own_stream(&d1, b"diff".to_vec(), false);
    wait(&mut a1rx, "a2 → a1 차이", got(&d2, b"diff")).await;

    // 시각이 흐른 뒤 다시 켬 — seq 는 지금 µs 에서 다시 가 남긴 것보다 크다(차이 프레임 뒤라도).
    a2.shutdown().await;
    drop(a2rx);
    h.fx.clock.advance(1_000);
    let (a2, mut a2rx) = h.start("alice", &a2k, 7, "a2.db");
    ready(&mut a2rx).await;
    a2.own_stream(&d1, b"after".to_vec(), false);
    wait(&mut a1rx, "다시 켠 뒤 흘림", got(&d2, b"after")).await;
    // 시각이 그대로(또는 뒤로)여도 마지막이 keyframe 이면 남긴 seq 위에서 이어 간다.
    a2.own_stream(&d1, b"key2".to_vec(), true);
    wait(&mut a1rx, "keyframe", got(&d2, b"key2")).await;
    a2.shutdown().await;
    drop(a2rx);
    let (a2, mut a2rx) = h.start("alice", &a2k, 7, "a2.db");
    ready(&mut a2rx).await;
    a2.own_stream(&d1, b"again".to_vec(), false);
    wait(&mut a1rx, "같은 시각에 다시 켠 뒤", got(&d2, b"again")).await;
}

/// 맥(alice 첫 기기)이 붙은 채 휴대폰(no_duty)을 더해 맥이 서명한다 — 나에게 글은 하나도 없다. 맥 흘림이 휴대폰에서 풀릴 때까지
/// 다시 보낸다(상한 수 초 — 시계를 돌리지 않음). 휴대폰 키·클라이언트·수신을 돌려준다.
async fn mac_then_phone(
    h: &Harness,
    mac: &RelayClient,
    mk: &DeviceKeys,
) -> (DeviceKeys, RelayClient, Receiver<Inbound>) {
    let pk = DeviceKeys::generate(&[7; 64]);
    let pi = DeviceInfo::of("alice", None, &pk);
    mac.plant_own_device(&pi).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &pi, true)
        .await
        .unwrap();
    let (phone, mut prx) = h.start_with("alice", &pk, 7, "phone.db", |c| c.no_duty = true);
    ready(&mut prx).await;
    let (md, pd) = (
        mk.device_id().as_str().to_owned(),
        pk.device_id().as_str().to_owned(),
    );
    let opened = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            mac.own_stream(&pd, b"state".to_vec(), true);
            let got = tokio::time::timeout(Duration::from_millis(500), async {
                loop {
                    match prx.recv().await {
                        Some(Inbound::OwnStream { from_device, data })
                            if from_device == md && data == b"state" =>
                        {
                            return true
                        }
                        Some(_) => {}
                        None => return false,
                    }
                }
            })
            .await;
            if got == Ok(true) {
                break;
            }
        }
    })
    .await;
    assert!(
        opened.is_ok(),
        "나에게 글 없는 새 계정 — 맥 흘림이 휴대폰에서 안 풀림(self 그룹을 아무도 안 만듦)"
    );
    assert_eq!(
        mac.own_devices(),
        vec![pd.clone()],
        "맥이 휴대폰을 받을 기기로"
    );
    for _ in 0..50 {
        if phone.own_devices() == vec![md.clone()] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(phone.own_devices(), vec![md], "휴대폰도 맥을(잎이 된 뒤)");
    (pk, phone, prx)
}

/// mobile-가입 ③ 덧 2(실기 확인 11-09 — 새 계정 휴대폰 '내 에이전트' 빈 화면): self 그룹은 나에게 글이 있어야 시작되고 relay duty 는
/// relay 에 있는 그룹에만 나와, 맥 + 휴대폰(no_duty) 새 계정엔 아무도 만들지 않았다. 맥이 붙은 채 휴대폰을 더하면 맥이 self 그룹을
/// 세워 휴대폰을 넣고, 내 기기 흘림이 수 초 안에 오간다.
#[tokio::test(flavor = "multi_thread")]
async fn 새_계정에_더한_휴대폰은_나에게_글_없이도_내_기기_흘림을_받는다() {
    let h = relay_cfg(true, |c| c.mobile_push = true).await;
    let mk = h.user("alice", 1).await;
    let (mac, mut mrx) = h.start("alice", &mk, 1, "mac.db");
    ready(&mut mrx).await;
    let (_pk, phone, _prx) = mac_then_phone(&h, &mac, &mk).await;
    // 반대로도(휴대폰 → 맥, own_sync 길).
    let md = mk.device_id().as_str().to_owned();
    phone.own_stream(&md, b"sync".to_vec(), false);
    wait(
        &mut mrx,
        "휴대폰 → 맥 흘림",
        |i| matches!(i, Inbound::OwnStream { data, .. } if data == b"sync"),
    )
    .await;
}

/// mobile-가입 ③ 덧 2-a: relay 에 self 그룹이 이미 있는 계정에 새 맥을 더하면 그 맥은 self 그룹을 시작하지 않는다 — group_info 답에
/// epoch 가 있어 그만두고 KeyPackage 를 가져오지 않는다(내 다른 기기 KeyPackage 를 헛되이 쓰지 않음). 맥은 duty Add 로 든다.
#[tokio::test(flavor = "multi_thread")]
async fn self_그룹이_relay_에_있으면_새_맥은_시작하지_않고_duty_로_든다() {
    let h = relay_cfg(true, |c| c.mobile_push = true).await;
    let mk = h.user("alice", 1).await;
    let (mac, mut mrx) = h.start("alice", &mk, 1, "mac.db");
    ready(&mut mrx).await;
    let (_pk, _phone, _prx) = mac_then_phone(&h, &mac, &mk).await;
    let nk = DeviceKeys::generate(&[8; 64]);
    let ni = DeviceInfo::of("alice", None, &nk);
    mac.plant_own_device(&ni).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &ni, true)
        .await
        .unwrap();
    let (_new, mut nrx) = h.start("alice", &nk, 8, "new.db");
    ready(&mut nrx).await;
    let (md, nd) = (
        mk.device_id().as_str().to_owned(),
        nk.device_id().as_str().to_owned(),
    );
    let joined = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            mac.own_stream(&nd, b"hi".to_vec(), true);
            let got = tokio::time::timeout(Duration::from_millis(500), async {
                loop {
                    match nrx.recv().await {
                        Some(Inbound::OwnStream { from_device, data })
                            if from_device == md && data == b"hi" =>
                        {
                            return true
                        }
                        Some(_) => {}
                        None => return false,
                    }
                }
            })
            .await;
            if got == Ok(true) {
                break;
            }
        }
    })
    .await;
    assert!(joined.is_ok(), "새 맥이 duty Add 로 self 그룹에 들지 않음");
    let claims = relay_i64(
        &h,
        &format!("SELECT COUNT(*) FROM mls_kp_claims WHERE claimer = '{nd}'"),
    );
    assert_eq!(
        claims, 0,
        "relay 에 있는 self 그룹을 새 맥이 다시 시작하려 함"
    );
}

/// 휴대폰 첫 기기(mobile-가입 ③): 휴대폰(no_duty)만 있는 계정에 나중에 맥을 '이 기기 추가'로 붙이면, 휴대폰이 붙어 있는 동안
/// relay 가 그 일의 붙은 후보가 no_duty 뿐이라 휴대폰에 duty 를 줘 맥이 수 초 안에 1:1 에 든다 — orphan 30분 길로 통과하면 안
/// 된다(시계를 돌리지 않는다). 붙기 전 글은 맥에 오지 않는다. 내 기기 그룹(self)은 둘이 된 뒤 생겨 흘림이 오간다(③ 덧 2 — 누가
/// 세우든). 맥은 디렉터리로 bob 을 동료로 안다.
#[tokio::test(flavor = "multi_thread")]
async fn 휴대폰_첫_기기_계정에_붙인_맥은_휴대폰이_바로_넣는다() {
    let h = relay_cfg(true, |c| c.mobile_push = true).await;
    let pk = h.user("alice", 1).await;
    let bk = h.user("bob", 2).await;
    let (phone, mut prx) = h.start_with("alice", &pk, 1, "phone.db", |c| c.no_duty = true);
    let (bob, mut brx) = h.start("bob", &bk, 2, "b.db");
    ready(&mut prx).await;
    ready(&mut brx).await;
    assert!(
        h.app.conns.duty_devices("alice").is_empty(),
        "휴대폰 하나뿐 — 평소 duty 후보 아님"
    );
    bob.enqueue(&Outgoing::Send {
        message: h.chat("bob@local", "alice@local", "붙기 전"),
    })
    .unwrap();
    assert_eq!(got_text(&mut prx).await, "붙기 전");

    // 맥: 같은 사람의 새 기기 — 휴대폰이 서명(확인)한다. 실제처럼 휴대폰보다 뒤에 등록(고정 시계면 added_at 이 같아 뿌리가
    // 기기 id 순으로 갈려, 맥이 뿌리가 되면 휴대폰 잎이 맥의 재서명 전까지 no_chain 이다 — 부하 중 거짓 실패).
    h.fx.clock.advance(1_000);
    let mk = DeviceKeys::generate(&[9; 64]);
    let mi = DeviceInfo::of("alice", None, &mk);
    phone.plant_own_device(&mi).unwrap();
    lodelai_relay_client::register::register_device_with(h.addr, TOKEN, &mi, true)
        .await
        .unwrap();
    let (mac, mut mrx) = h.start("alice", &mk, 9, "mac.db");
    ready(&mut mrx).await;
    // 수 초 상한 — 시계를 앞으로 돌리지 않는다(orphan 30분 금지).
    let joined = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            bob.enqueue(&Outgoing::Send {
                message: h.chat("bob@local", "alice@local", "붙은 뒤"),
            })
            .unwrap();
            if let Ok(t) = tokio::time::timeout(Duration::from_secs(2), got_text(&mut mrx)).await {
                break t;
            }
        }
    })
    .await
    .expect("맥이 휴대폰 duty 로 1:1 에 들지 않음(orphan 길만 남음)");
    assert_eq!(joined, "붙은 뒤", "붙기 전 글은 맥에 오지 않는다");

    // 내 기기 흘림: 맥 → 휴대폰이 수 초 안에 풀린다.
    let (md, pd) = (
        mk.device_id().as_str().to_owned(),
        pk.device_id().as_str().to_owned(),
    );
    let opened = tokio::time::timeout(Duration::from_secs(20), async {
        loop {
            mac.own_stream(&pd, b"state".to_vec(), true);
            let got = tokio::time::timeout(Duration::from_millis(500), async {
                loop {
                    match prx.recv().await {
                        Some(Inbound::OwnStream { from_device, data })
                            if from_device == md && data == b"state" =>
                        {
                            return true
                        }
                        Some(_) => {}
                        None => return false,
                    }
                }
            })
            .await;
            if got == Ok(true) {
                break;
            }
        }
    })
    .await;
    assert!(
        opened.is_ok(),
        "휴대폰 첫 계정 — 맥 흘림이 휴대폰에서 안 풀림"
    );
    // 맥은 bob 을 동료로 안다(디렉터리).
    let d = mac.directory();
    assert!(
        d["people"]
            .as_array()
            .into_iter()
            .flatten()
            .any(|p| p["address"] == "bob@local"),
        "{d}"
    );
    drop(phone);
}

/// #881: 지난 대화 조각은 받을 기기 하나만 받는다 — 올린 내 기기도 못 받고, 조각 키가 다르면 못 열고, 받은 뒤 지우면 없다.
#[tokio::test(flavor = "multi_thread")]
async fn 지난_대화_조각은_받을_기기만_받아_연다() {
    use lodelai_relay_client::Error;
    use zeroize::Zeroizing;
    let h = relay().await;
    let ak = h.user("alice", 1).await;
    let (a1, mut a1rx) = h.start("alice", &ak, 1, "a.db");
    ready(&mut a1rx).await;
    let (a2k, a2, _a2rx) = second_own_device(&h, &a1, &ak).await;
    let d2 = a2k.device_id().as_str().to_owned();
    let t = Duration::from_secs(20);
    let key = || Zeroizing::new([7u8; 32]);
    let plain: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();

    let blob = a1.history_put(&d2, key(), plain.clone(), t).await.unwrap();
    assert!(blob.size > plain.len() as u64);
    // 올린 기기는 받지 못한다(relay 가 받을 기기만 표를 준다).
    assert!(matches!(
        a1.history_get(blob.clone(), key(), 1 << 20, t).await,
        Err(Error::Relay(_))
    ));
    // 풀린 크기 상한보다 큰 조각은 묻지도 않는다.
    assert!(matches!(
        a2.history_get(blob.clone(), key(), 1000, t).await,
        Err(Error::Relay(c)) if c == "protocol"
    ));
    // 조각 키가 다르면 못 연다.
    assert!(matches!(
        a2.history_get(blob.clone(), Zeroizing::new([8u8; 32]), 1 << 20, t)
            .await,
        Err(Error::Message(_))
    ));
    assert_eq!(
        a2.history_get(blob.clone(), key(), 1 << 20, t)
            .await
            .unwrap(),
        plain
    );
    // 받은 뒤 지우면 relay 에 없다.
    a2.history_fetched(&blob.blob_id);
    let mut gone = false;
    for _ in 0..50 {
        if a2
            .history_get(blob.clone(), key(), 1 << 20, t)
            .await
            .is_err()
        {
            gone = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(gone, "blob.fetched 뒤에도 조각이 남아 있다");
    // 내 기기가 아닌 기기 앞으로는 올리지 못한다.
    assert!(matches!(
        a1.history_put("k1_AAAAAAAAAAAAAAAAAAAAAA", key(), plain, t)
            .await,
        Err(Error::Relay(_))
    ));
}
