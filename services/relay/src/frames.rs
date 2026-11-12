//! WebSocket 프레임(protocol §7.2, `packages/protocol/schema/ws.schema.json`)과 메시지 헤더 읽기(§3).
//!
//! 경계는 생성 타입(`lodelai_protocol::ws`, #52·#126)을 거친다: 들어오는 프레임은 `ws::Frame` 으로 **스키마 검사**(패턴·
//! `additionalProperties:false`·판별 필드)를 통과해야 하고, 나가는 프레임은 생성 타입으로 만들어 직렬화한다.
//! relay 내부는 아래의 작은 enum 으로 다룬다. `deliver` 의 `message` 는 서명이 걸린 **원본 JSON 을 그대로** 보낸다.
//! 메시지 본문은 해석하지 않는다 — 라우팅에 필요한 헤더만 `serde_json::Value` 에서 읽는다.

use lodelai_protocol::ws;
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// 클라이언트 → 서버. [`ClientFrame::parse`] 로만 만든다.
#[derive(Debug, Clone)]
pub enum ClientFrame {
    Hello {
        v: u32,
        device_id: String,
        user: String,
        /// 모바일 검증: duty 후보에서 빠지는 연결(휴대폰).
        no_duty: bool,
        /// #874: 디렉터리 look 을 아는 연결.
        look: bool,
        /// #870·#872: 내 기기끼리 글·own_stream 을 아는 연결.
        own: bool,
        /// #845: 연락처(link.*·디렉터리 links·link_requests)를 아는 연결.
        contacts: bool,
        /// #845 §7-56: 디렉터리 mutes 를 아는 연결.
        mutes: bool,
        /// #880: 디렉터리 pins 를 아는 연결.
        pins: bool,
        /// #870: 디렉터리 내 기기 항목 away 를 아는 연결.
        away: bool,
    },
    Auth {
        sig: String,
    },
    /// `message` 는 스키마 검사를 통과한 **원본 JSON**(서명 검증·보관·전달에 그대로 쓴다).
    Send {
        message: Value,
    },
    DeliveredAck {
        msg_id: String,
        /// 0.2.6 #809: 그 기기가 열지 못했다(`delivered_ack.unreadable`).
        unreadable: bool,
    },
    Status {
        msg_id: String,
        state: String,
        abort_reason: Option<String>,
        /// `state == failed` 일 때의 사유 코드(#134).
        fail_reason: Option<String>,
        at: String,
    },
    SessionPublish {
        slug: String,
        grade: String,
        liveness: String,
        display: Option<String>,
        title: Option<String>,
        folder: Option<String>,
        /// 프로젝트 (id, 구분 이름)(묶음 23 §5). 이름은 아직 검사 전 — 처리할 때 normalize_project_name.
        project: Option<(String, String)>,
        capabilities: Option<Vec<String>>,
        busy: bool,
        /// 공개 범위(묶음 20). 없으면 조직 전체. 값은 아직 검사 전 — 처리할 때 검사.
        audience: Option<ws::Audience>,
        /// 에이전트 종류(Codex C2, PROTOCOL 13) — 꼴은 스키마가 봤다. 없으면 claude_code.
        agent: Option<String>,
        /// 주인 코어의 같은 이름 번호(관문 Y2, PROTOCOL 13). 1..=999 만 남긴다 — 밖이면 칸만 버린다(프레임은 받음).
        no: Option<u16>,
    },
    SessionUnpublish {
        slug: String,
    },
    DirectoryList,
    /// 내 표시 이름·팀 변경(#326·#355). 없는 필드는 안 바꾼다. 값은 아직 검사 전 — 처리할 때 검사.
    ProfileUpdate {
        display_name: Option<String>,
        teams: Option<Vec<String>>,
        /// `avatar: null`(묶음 15 §2) — 프로필 사진 지우기. null 이 아닌 값은 생성 타입이 거절한다.
        clear_avatar: bool,
        /// #874 `look`: 없음 = 안 바꿈, `Some(None)` = 기본으로, `Some(Some(json))` = 고름(꼴은 생성 타입이 이미 봤다 — 정규 JSON).
        look: Option<Option<String>>,
    },
    /// 조직 관리자 동작(#355). 관리자 판정·이름 규칙 검사는 처리할 때. 둘 다 없으면 처리할 때 거절.
    OrgUpdate {
        name: Option<String>,
        /// `avatar: null`(#554) — 조직 사진 지우기. null 이 아닌 값은 생성 타입이 거절한다.
        clear_avatar: bool,
        /// 조직 고유색: 없음 = 안 바꿈, `Some(None)` = 지움, `Some(Some(c))` = 정함(꼴은 생성 타입이 봤다).
        color: Option<Option<String>>,
        /// #845 둘째 ② 조직 밖 연락 막기: 없음 = 안 바꿈, `Some(true)` = 막음(closed), `Some(false)` = 엶(null).
        external: Option<bool>,
    },
    TeamCreate {
        name: String,
    },
    TeamUpdate {
        id: String,
        name: String,
    },
    TeamDelete {
        id: String,
    },
    InviteCreate {
        email: Option<String>,
    },
    /// 기기 폐기. `device_id` 가 없으면 이 연결의 기기 자신(#325), 있으면 같은 사용자의 그 기기(#339).
    DeviceRevoke {
        device_id: Option<String>,
        /// 묶음 22 devrevoke 증명 (at, sig) — 서명자는 이 연결의 기기. 검증은 처리할 때.
        proof: Option<(String, String)>,
    },
    /// 내 기기 서명(#393). 이 연결의 기기가 같은 사용자의 `device_id` 에 한 `lodelai-devcert-v1` 서명 — 검증은 처리할 때.
    DeviceCertify {
        device_id: String,
        sig: String,
    },
    /// 메일 확인 끊기(#577): 걸기·건 쪽 취소·대상 쪽 막기. 조건은 처리할 때.
    DeviceRecover,
    DeviceRecoverCancel,
    DeviceRecoverBlock,
    /// 원격 relay 의 관리자가 새 기기를 등록(#364). `code` 는 기기 연결 코드 — 검증은 처리할 때.
    DeviceRegister {
        code: String,
    },
    /// 관리자 주기·빼기(묶음 5). 관리자 판정은 처리할 때.
    OrgAdmin {
        user: String,
        admin: bool,
    },
    /// 내보내기(묶음 5).
    MemberRemove {
        user: String,
    },
    /// 관리자가 같은 조직 다른 사람의 옛 기기를 지금 끊는다(#737 — 메일 확인 끊기 대상만).
    MemberRevokeDevice {
        user: String,
        device_id: String,
    },
    /// 조직 나가기(묶음 5, 서버 relay 만).
    MemberLeave,
    /// #877 조직에서 나가 개인 공간으로(서버 relay 만, 계정은 남음).
    OrgLeave,
    /// 이 기기의 이름(#490 묶음 28 §4). 값은 아직 검사 전 — 처리할 때 NFC·규칙 검사.
    DeviceName {
        name: String,
        /// 판 15: 기기가 알린 OS(스키마 enum 값). 표시용.
        os: Option<String>,
    },
    /// 서버 상태 조회(묶음 5, 원격 관리자만).
    ServerStatus,
    /// 접속 표시를 같은 조직에 보일지(묶음 14 B1).
    PresenceSet {
        share: bool,
    },
    /// 입력 중 표시(묶음 36 #613) — `to` 는 사람 또는 그룹 주소(스키마가 세션 주소를 막는다).
    Typing {
        to: String,
        on: bool,
    },
    /// 내 기기 하나에 흘림(#870) — 저장·응답 없음, `data` 는 relay 가 모르는 AEAD 암호문(base64url).
    OwnStream {
        to_device: String,
        epoch: u64,
        seq: u64,
        data: String,
    },
    /// 내 맥에 사람 손이 필요한 일이 생김(#870 카드·#890 사용량 한도 가까움 `usage`) — 붙지 않은 내 다른 기기에 종류별 고정
    /// 문구 푸시. 응답 없음.
    OwnAlert {
        usage: bool,
    },
    /// #845 연락 요청 — 정확한 이메일(정규화 전) 또는 아이디 하나.
    LinkRequest {
        req: Option<String>,
        to: LinkTo,
    },
    /// #845 받은 요청에 답.
    LinkAnswer {
        id: String,
        answer: LinkAnswerKind,
    },
    /// #845 연락처 빼기(상대 아이디).
    LinkRemove {
        peer: String,
        /// §7-8: 빼면서 막기.
        block: bool,
    },
    /// #845 연락처에게 task 열기/닫기(상대 아이디).
    LinkUpdate {
        peer: String,
        task_ok: bool,
    },
    /// #845 §7-9 내가 보낸 요청 거두기(outgoing id).
    LinkWithdraw {
        id: String,
    },
    /// 관문 A6 내가 막은 사람 풀기(상대 아이디). 답 link.sent(req).
    LinkUnblock {
        req: Option<String>,
        peer: String,
    },
    /// #845 ③ 내 초대 링크 토큰(`rotate` = 다시 만들기).
    ContactLink {
        req: Option<String>,
        rotate: bool,
    },
    /// #845 ③ 남의 초대 링크로 연락처 맺기.
    LinkJoin {
        req: Option<String>,
        token: String,
    },
    /// #845 §7-23 남의 연락처 링크 미리보기.
    ContactLinkPreview {
        req: Option<String>,
        token: String,
    },
    /// #845 ④ 조직 관리자의 이메일 초대(정규화 전).
    OrgInvite {
        req: Option<String>,
        email: String,
    },
    /// #845 ④ 받은 조직 초대에 답.
    OrgInviteAnswer {
        id: String,
        accept: bool,
    },
    /// #845 §7-56 계정 단위 대화 음소거. `until` 없음 = 계속, `clear` = 풂(null).
    /// #845 둘째 친구 목록 통째 덮어쓰기.
    ListPut {
        req: Option<String>,
        list_id: String,
        name: String,
        users: Vec<String>,
    },
    /// #845 둘째 친구 목록 지우기.
    ListDelete {
        req: Option<String>,
        list_id: String,
    },
    MuteSet {
        req: Option<String>,
        conv: String,
        until: Option<String>,
        clear: bool,
    },
    /// #880 계정 단위 대화 고정 한 동작. `index` = 넣을 자리, `None` = 풂.
    PinSet {
        req: Option<String>,
        conv: String,
        index: Option<i64>,
    },
    /// #845 §7-46 조직 초대 코드 카드(읽기만).
    OrgCodeCheck {
        req: Option<String>,
        code: String,
    },
    /// #845 둘째 ③ 조직 밖 막기를 켜기 전 조직 전체 셈(관리자만, 읽기만).
    OrgExternalPreview {
        req: Option<String>,
    },
    /// #845 §7-46 개인 공간 → 초대 코드로 조직 들기.
    OrgJoin {
        req: Option<String>,
        code: String,
        teams: Vec<String>,
    },
    /// #845 §7-46 개인 공간 → 조직 만들기(이름은 정리 전).
    OrgCreate {
        req: Option<String>,
        name: String,
        setup_code: Option<String>,
    },
    /// #845 ④ 그룹 초대(그룹 주소, 이메일 또는 아이디).
    GroupInvite {
        req: Option<String>,
        group: String,
        to: LinkTo,
    },
    /// #845 ④ 받은 그룹 초대에 답.
    GroupInviteAnswer {
        id: String,
        accept: bool,
    },
    /// #845 §7-26 보낸 조직 초대 거두기(관리자).
    OrgInviteWithdraw {
        id: String,
    },
    /// #845 §7-26 보낸 그룹 초대 거두기(보낸 사람).
    GroupInviteWithdraw {
        id: String,
    },
    /// 묶음 22 §3: 이 기기의 KeyPackage 올리기.
    KeyPackagesPublish {
        items: Vec<String>,
        last_resort: Option<String>,
        /// 0.2.5(g025f B): 이 기기의 남은 KeyPackage 를 지우고 바꾼다(데이터를 잃은 기기의 첫 올리기).
        reset: bool,
    },
    /// 묶음 22 §3: 기기마다 KeyPackage 하나 가져가기.
    KeyPackagesClaim {
        device_ids: Vec<String>,
    },
    /// 묶음 22 §5b: 그 그룹의 최신 GroupInfo(base64url 그룹 id).
    GroupInfoGet {
        group: String,
    },
    /// #882 맥의 현황 숫자(ADR 0014) — 응답 없음.
    OwnLive {
        busy: u32,
        approval: u32,
        question: u32,
        oldest_ms: Option<i64>,
    },
    /// #882 이 기기의 현황 받기·Live Activity 토큰(늘 지금 상태 전부).
    PushLive {
        req: String,
        on: bool,
        start_token: Option<String>,
        /// (갱신 토큰, 활동 시작 ms).
        activity: Option<(String, i64)>,
    },
    /// 모바일 검증: 이 기기의 푸시 토큰(`push.register`).
    PushRegister {
        req: String,
        apns: bool,
        token: String,
        sandbox: bool,
        app_id: String,
        /// #845 §7-55 끈 알림 갈래(`chat`·`group`·`agents`·`invite`).
        off: Vec<String>,
    },
    /// 모바일 검증: `push.unregister`.
    PushUnregister {
        req: String,
    },
    /// 첨부 올리기 예약(묶음 15). `avatar` 면 `avatar = true`, `for: org`(#554) 면 `for_org = true`.
    BlobReserve {
        req: String,
        ct_len: u64,
        avatar: bool,
        for_org: bool,
        /// #881 지난 대화 옮기기 조각의 받을 기기.
        for_device: Option<String>,
    },
    /// 첨부 받기 표(묶음 15).
    BlobGet {
        req: String,
        blob_id: String,
    },
    /// 이 기기가 첨부를 받았다(묶음 15).
    BlobFetched {
        blob_id: String,
    },
    /// 내 그룹 목록(묶음 16).
    GroupsList,
    /// 그룹 변경 다시 받기(묶음 16).
    GroupsReplay {
        group: String,
        from_seq: u64,
    },
    /// 확정 전 Commit 응답(묶음 22 §4-7): ack 면 처리됨, 아니면 처리 실패.
    CommitVote {
        group: String,
        epoch: u64,
        commit_hash: String,
        ack: bool,
    },
    Ping,
    Pong,
}

/// #845 `link.request` 의 대상.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkTo {
    Email(String),
    User(String),
}

/// #845 `link.answer` 의 답.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkAnswerKind {
    Accept,
    Decline,
    Block,
}

impl ClientFrame {
    /// 텍스트 프레임 하나. 스키마(`ws::Frame`)에 맞지 않거나 서버→클라이언트 전용 프레임이면 `None`.
    pub fn parse(text: &str) -> Option<Self> {
        let raw: Value = serde_json::from_str(text).ok()?;
        let typed: ws::Frame = serde_json::from_value(raw.clone()).ok()?;
        Some(match typed {
            ws::Frame::Hello(h) => Self::Hello {
                v: u32::try_from(h.v).unwrap_or(u32::MAX),
                device_id: h.device_id.to_string(),
                user: h.user.to_string(),
                no_duty: h.no_duty.unwrap_or(false),
                look: h.look.unwrap_or(false),
                own: h.own.unwrap_or(false),
                contacts: h.contacts.unwrap_or(false),
                mutes: h.mutes.unwrap_or(false),
                pins: h.pins.unwrap_or(false),
                away: h.away.unwrap_or(false),
            },
            ws::Frame::Auth(a) => Self::Auth {
                sig: a.sig.to_string(),
            },
            ws::Frame::Send(_) => Self::Send {
                message: raw.get("message")?.clone(),
            },
            ws::Frame::DeliveredAck(d) => Self::DeliveredAck {
                msg_id: d.msg_id.to_string(),
                unreadable: d.unreadable.unwrap_or(false),
            },
            // `by` 는 S→C 만(묶음 16 §4) — 클라이언트가 실으면 error{protocol}.
            ws::Frame::Status(st) if st.by.is_some() => return None,
            ws::Frame::Status(st) => Self::Status {
                msg_id: st.msg_id.to_string(),
                state: st.state.to_string(),
                abort_reason: st.abort_reason.map(|a| a.as_str().to_owned()),
                fail_reason: st.fail_reason.map(|f| f.to_string()),
                at: st.at.to_string(),
            },
            ws::Frame::SessionPublish(p) => Self::SessionPublish {
                slug: p.slug.to_string(),
                grade: p.grade.to_string(),
                liveness: p.liveness.to_string(),
                display: p.display.map(|d| d.to_string()),
                title: p.title.map(|t| t.to_string()),
                folder: p.folder.map(|f| f.to_string()),
                project: p.project.map(|x| (x.id.to_string(), x.name.to_string())),
                capabilities: Some(p.capabilities),
                busy: p.busy == Some(true),
                audience: p.audience,
                agent: p.agent.map(|a| a.to_string()),
                no: p
                    .no
                    .and_then(|n| u16::try_from(n).ok())
                    .filter(|n| (1..=999).contains(n)),
            },
            ws::Frame::SessionUnpublish(u) => Self::SessionUnpublish { slug: u.slug },
            ws::Frame::DirectoryList(_) => Self::DirectoryList,
            // #874: 생성 타입은 tone 의 상한(6)을 보지 않는다 — 여기서 형식 오류로.
            ws::Frame::ProfileUpdate(p)
                if matches!(&p.look,
                    Some(ws::Look::Initial { tone })
                    | Some(ws::Look::Character { tone: Some(tone), .. }) if tone.get() > 6) =>
            {
                return None
            }
            ws::Frame::ProfileUpdate(p) => Self::ProfileUpdate {
                display_name: p.display_name.map(|d| d.to_string()),
                // 생성 타입은 빈 배열과 "없음" 을 가르지 못한다 — 없는 필드 = 안 바꿈이라 원본에서 본다(#355).
                teams: raw
                    .get("teams")
                    .map(|_| p.teams.iter().map(|t| t.to_string()).collect()),
                // 생성 타입은 `avatar: ()` 라 키가 있었는지 모른다 — 원본에서 본다.
                clear_avatar: raw.get("avatar").is_some_and(Value::is_null),
                // null 과 없음을 생성 타입이 가르지 못한다 — 키는 원본에서, 값은 검사한 생성 타입에서 다시 쓴다.
                look: raw
                    .get("look")
                    .map(|_| p.look.as_ref().and_then(|l| serde_json::to_string(l).ok())),
            },
            ws::Frame::OrgUpdate(o) => Self::OrgUpdate {
                name: o.name.map(|n| n.to_string()),
                // 생성 타입은 `avatar: ()` 라 키가 있었는지 모른다 — 원본에서 본다.
                clear_avatar: raw.get("avatar").is_some_and(Value::is_null),
                // null 과 없음을 생성 타입이 가르지 못한다 — 키는 원본에서.
                color: raw
                    .get("color")
                    .map(|_| o.color.as_ref().map(|c| c.as_str().to_owned())),
                external: raw.get("external").map(|_| o.external.is_some()),
            },
            ws::Frame::TeamCreate(c) => Self::TeamCreate {
                name: c.name.to_string(),
            },
            ws::Frame::TeamUpdate(u) => Self::TeamUpdate {
                id: u.id.to_string(),
                name: u.name.to_string(),
            },
            ws::Frame::TeamDelete(d) => Self::TeamDelete {
                id: d.id.to_string(),
            },
            ws::Frame::InviteCreate(i) => Self::InviteCreate {
                email: i.email.map(|e| e.to_string()),
            },
            ws::Frame::DeviceRevoke(d) => Self::DeviceRevoke {
                device_id: d.device_id.map(|id| id.to_string()),
                proof: d.proof.map(|p| (p.at.to_string(), p.sig.to_string())),
            },
            ws::Frame::DeviceCertify(c) => Self::DeviceCertify {
                device_id: c.device_id.to_string(),
                sig: c.sig.to_string(),
            },
            ws::Frame::DeviceRegister(r) => Self::DeviceRegister {
                code: r.code.to_string(),
            },
            ws::Frame::OrgAdmin(a) => Self::OrgAdmin {
                user: a.user.to_string(),
                admin: a.admin,
            },
            ws::Frame::MemberRemove(m) => Self::MemberRemove {
                user: m.user.to_string(),
            },
            ws::Frame::MemberRevokeDevice(m) => Self::MemberRevokeDevice {
                user: m.user.to_string(),
                device_id: m.device_id.to_string(),
            },
            ws::Frame::MemberLeave(_) => Self::MemberLeave,
            ws::Frame::OrgLeave(_) => Self::OrgLeave,
            ws::Frame::DeviceName(d) => Self::DeviceName {
                name: d.name.to_string(),
                os: d.os.map(|o| o.to_string()),
            },
            ws::Frame::ServerStatusRequest(_) => Self::ServerStatus,
            ws::Frame::PresenceSet(p) => Self::PresenceSet { share: p.share },
            ws::Frame::Typing(t) => Self::Typing {
                to: match &t.to {
                    ws::TypingTo::PersonAddress(a) => a.to_string(),
                    ws::TypingTo::GroupAddress(a) => a.to_string(),
                },
                on: t.on,
            },
            ws::Frame::OwnStream(o) => Self::OwnStream {
                to_device: o.to_device.to_string(),
                epoch: o.epoch,
                seq: o.seq,
                data: o.data.to_string(),
            },
            ws::Frame::OwnAlert(a) => Self::OwnAlert {
                usage: matches!(a.kind, Some(ws::OwnAlertKind::Usage)),
            },
            ws::Frame::LinkRequest(l) => Self::LinkRequest {
                req: l.req.map(|r| r.to_string()),
                to: match (l.email, l.user) {
                    (Some(e), None) => LinkTo::Email(e.to_string()),
                    (None, Some(u)) => LinkTo::User(u.to_string()),
                    _ => return None,
                },
            },
            ws::Frame::LinkAnswer(a) => Self::LinkAnswer {
                id: a.id.to_string(),
                answer: match a.answer {
                    ws::LinkAnswerAnswer::Accept => LinkAnswerKind::Accept,
                    ws::LinkAnswerAnswer::Decline => LinkAnswerKind::Decline,
                    ws::LinkAnswerAnswer::Block => LinkAnswerKind::Block,
                },
            },
            ws::Frame::LinkRemove(r) => Self::LinkRemove {
                peer: r.peer.to_string(),
                block: r.block.unwrap_or(false),
            },
            ws::Frame::LinkUpdate(u) => Self::LinkUpdate {
                peer: u.peer.to_string(),
                task_ok: u.task_ok,
            },
            ws::Frame::LinkWithdraw(w) => Self::LinkWithdraw {
                id: w.id.to_string(),
            },
            ws::Frame::LinkUnblock(u) => Self::LinkUnblock {
                req: u.req.map(|r| r.to_string()),
                peer: u.peer.to_string(),
            },
            ws::Frame::ContactLinkGet(g) => Self::ContactLink {
                req: g.req.map(|r| r.to_string()),
                rotate: false,
            },
            ws::Frame::ContactLinkRotate(g) => Self::ContactLink {
                req: g.req.map(|r| r.to_string()),
                rotate: true,
            },
            ws::Frame::LinkJoin(j) => Self::LinkJoin {
                req: j.req.map(|r| r.to_string()),
                token: j.token.to_string(),
            },
            ws::Frame::ContactLinkPreview(p) => Self::ContactLinkPreview {
                req: p.req.map(|r| r.to_string()),
                token: p.token.to_string(),
            },
            ws::Frame::OrgInvite(i) => Self::OrgInvite {
                req: i.req.map(|r| r.to_string()),
                email: i.email.to_string(),
            },
            ws::Frame::OrgInviteAnswer(a) => Self::OrgInviteAnswer {
                id: a.id.to_string(),
                accept: matches!(a.answer, ws::OrgInviteAnswerAnswer::Accept),
            },
            ws::Frame::ListPut(l) => Self::ListPut {
                req: l.req.map(|r| r.to_string()),
                list_id: String::from(l.list_id),
                name: l.name.to_string(),
                users: l.users.into_iter().map(String::from).collect(),
            },
            ws::Frame::ListDelete(l) => Self::ListDelete {
                req: l.req.map(|r| r.to_string()),
                list_id: String::from(l.list_id),
            },
            ws::Frame::MuteSet(m) => Self::MuteSet {
                req: m.req.map(|r| r.to_string()),
                conv: m.conv.to_string(),
                until: m.until.map(|u| u.to_string()),
                // 생성 타입은 null 과 없음을 가르지 않는다 — 원본에서 본다.
                clear: raw.get("until").is_some_and(Value::is_null),
            },
            ws::Frame::PinSet(p) => Self::PinSet {
                req: p.req.map(|r| r.to_string()),
                conv: p.conv.to_string(),
                index: p.index,
            },
            ws::Frame::OrgCodeCheck(c) => Self::OrgCodeCheck {
                req: c.req.map(|r| r.to_string()),
                code: c.code.to_string(),
            },
            ws::Frame::OrgExternalPreview(p) => Self::OrgExternalPreview {
                req: p.req.map(|r| r.to_string()),
            },
            ws::Frame::OrgJoin(j) => Self::OrgJoin {
                req: j.req.map(|r| r.to_string()),
                code: j.code.to_string(),
                teams: j.teams.into_iter().map(|t| t.to_string()).collect(),
            },
            ws::Frame::OrgCreate(c) => Self::OrgCreate {
                req: c.req.map(|r| r.to_string()),
                name: c.name.to_string(),
                setup_code: c.setup_code.map(|x| x.to_string()),
            },
            ws::Frame::GroupInvite(i) => Self::GroupInvite {
                req: i.req.map(|r| r.to_string()),
                group: i.group.to_string(),
                to: match (i.email, i.user) {
                    (Some(e), None) => LinkTo::Email(e.to_string()),
                    (None, Some(u)) => LinkTo::User(u.to_string()),
                    _ => return None,
                },
            },
            ws::Frame::GroupInviteAnswer(a) => Self::GroupInviteAnswer {
                id: a.id.to_string(),
                accept: matches!(a.answer, ws::GroupInviteAnswerAnswer::Accept),
            },
            ws::Frame::OrgInviteWithdraw(w) => Self::OrgInviteWithdraw {
                id: w.id.to_string(),
            },
            ws::Frame::GroupInviteWithdraw(w) => Self::GroupInviteWithdraw {
                id: w.id.to_string(),
            },
            ws::Frame::GroupsList(_) => Self::GroupsList,
            ws::Frame::GroupsReplay(r) => Self::GroupsReplay {
                group: r.group.to_string(),
                from_seq: r.from_seq.get(),
            },
            ws::Frame::OwnLive(l) => Self::OwnLive {
                busy: u32::try_from(l.busy).ok()?,
                approval: u32::try_from(l.approval).ok()?,
                question: u32::try_from(l.question).ok()?,
                oldest_ms: match l.oldest {
                    Some(t) => Some(lodelai_effects::UnixMillis::parse_rfc3339(&t).ok()?.0),
                    None => None,
                },
            },
            ws::Frame::PushLive(p) => Self::PushLive {
                req: p.req.to_string(),
                on: p.on,
                start_token: p.start_token.map(|t| t.to_string()),
                activity: match p.activity {
                    Some(a) => Some((
                        a.token.to_string(),
                        lodelai_effects::UnixMillis::parse_rfc3339(&a.started)
                            .ok()?
                            .0,
                    )),
                    None => None,
                },
            },
            ws::Frame::PushRegister(p) => Self::PushRegister {
                req: p.req.to_string(),
                apns: p.platform == ws::PushRegisterPlatform::Apns,
                token: p.token.to_string(),
                sandbox: p.env == ws::PushRegisterEnv::Sandbox,
                app_id: p.app_id.to_string(),
                off: p
                    .off
                    .unwrap_or_default()
                    .iter()
                    .map(ToString::to_string)
                    .collect(),
            },
            ws::Frame::PushUnregister(p) => Self::PushUnregister {
                req: p.req.to_string(),
            },
            ws::Frame::BlobReserve(b) => Self::BlobReserve {
                req: b.req.to_string(),
                ct_len: b.ct_len.get(),
                avatar: b.purpose == ws::BlobReservePurpose::Avatar,
                for_org: b.for_.is_some(),
                for_device: b.for_device.as_ref().map(|d| d.to_string()),
            },
            ws::Frame::BlobGet(b) => Self::BlobGet {
                req: b.req.to_string(),
                blob_id: b.blob_id.to_string(),
            },
            ws::Frame::BlobFetched(b) => Self::BlobFetched {
                blob_id: b.blob_id.to_string(),
            },
            ws::Frame::Ping(_) => Self::Ping,
            ws::Frame::Pong(_) => Self::Pong,
            // 묶음 22 MLS(전달 서비스 구현 전): 아직 받지 않는다 — error{protocol}.
            ws::Frame::KeyPackagesPublish(p) => Self::KeyPackagesPublish {
                items: p.items.into_iter().map(String::from).collect(),
                last_resort: p.last_resort.map(String::from),
                reset: p.reset.unwrap_or(false),
            },
            ws::Frame::KeyPackagesClaim(c) => Self::KeyPackagesClaim {
                device_ids: c.device_ids.iter().map(|d| (**d).clone()).collect(),
            },
            ws::Frame::GroupInfoGet(g) => Self::GroupInfoGet {
                group: (*g.group).clone(),
            },
            ws::Frame::CommitAck(c) => Self::CommitVote {
                group: (*c.group).clone(),
                epoch: c.epoch,
                commit_hash: (*c.commit_hash).clone(),
                ack: true,
            },
            ws::Frame::CommitFail(c) => Self::CommitVote {
                group: (*c.group).clone(),
                epoch: c.epoch,
                commit_hash: (*c.commit_hash).clone(),
                ack: false,
            },
            // 서버 → 클라이언트 전용
            ws::Frame::Challenge(_)
            | ws::Frame::Ready(_)
            | ws::Frame::Ack(_)
            | ws::Frame::Nack(_)
            | ws::Frame::Deliver(_)
            | ws::Frame::Directory(_)
            | ws::Frame::DirectoryUpdate(_)
            | ws::Frame::DeviceRevoked(_)
            | ws::Frame::InviteCreated(_)
            | ws::Frame::DeviceRegistered(_)
            | ws::Frame::ServerStatus(_)
            | ws::Frame::KeyPackagesLow(_)
            | ws::Frame::KeyPackages(_)
            | ws::Frame::GroupInfo(_)
            | ws::Frame::CommitFinal(_)
            | ws::Frame::CommitVoid(_)
            | ws::Frame::GroupAlert(_)
            | ws::Frame::Duty(_)
            | ws::Frame::RejoinNeeded(_)
            | ws::Frame::BlobReserved(_)
            | ws::Frame::PushOk(_)
            | ws::Frame::PushLiveOk(_)
            | ws::Frame::OwnLiveWant(_)
            | ws::Frame::BlobTicket(_)
            | ws::Frame::Groups(_)
            | ws::Frame::DeviceRecoverScheduled(_)
            | ws::Frame::DeviceRecoverCanceled(_)
            | ws::Frame::DeviceRecoverAgainst(_)
            | ws::Frame::DeviceRecoverAgainstEnded(_)
            | ws::Frame::DeviceRecovered(_)
            | ws::Frame::TypingNotice(_)
            | ws::Frame::OwnStreamNotice(_)
            | ws::Frame::LinkSent(_)
            | ws::Frame::ContactLink(_)
            | ws::Frame::OrgInviteSent(_)
            | ws::Frame::ContactLinkPreviewAnswer(_)
            | ws::Frame::OrgCodeCheckAnswer(_)
            | ws::Frame::OrgExternalPreviewAnswer(_)
            | ws::Frame::OrgJoinAnswer(_)
            | ws::Frame::OrgCreateAnswer(_)
            | ws::Frame::GroupInviteSent(_)
            | ws::Frame::Error(_) => return None,
            ws::Frame::DeviceRecover(_) => Self::DeviceRecover,
            ws::Frame::DeviceRecoverCancel(_) => Self::DeviceRecoverCancel,
            ws::Frame::DeviceRecoverBlock(_) => Self::DeviceRecoverBlock,
        })
    }
}

/// `nack.reason`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NackReason {
    Auth,
    Unroutable,
    TooLarge,
    /// 봉투 `recipients` 에 받는 사용자의 기기가 아닌 것이 있다(#313, protocol §7.2-6a).
    StaleDevices,
    /// 묶음 22: pair·self 의 두 번째 start(§2a).
    EpochTaken,
    /// 묶음 22: 지금 epoch 가 아님(§4-1·§12-11 ⓑ).
    StaleEpoch,
    /// 묶음 22: Commit 검사(§4 1~5) 실패 — 이유는 로그에만.
    InvalidCommit,
    /// 묶음 22: 쥐고 있던 N+1 응용 메시지 — Commit 무효(§4-7).
    CommitVoid,
    /// 묶음 22: Commit 속도 상한(§4-6).
    RateLimited,
    /// 헤더 `blobs` 중 보낸 사용자가 올린 묶이지 않은 첨부가 아닌 것이 있다(묶음 15).
    BlobUnavailable,
}

/// `error.code`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    RateLimited,
    Protocol,
    Internal,
    /// 나중 기기가 먼저 기기를 등록 뒤 24시간 전에 폐기하려 했다(#339).
    TooEarly,
    /// 폐기된 기기가 자기 키로 맞게 서명해 접속했다(#339) — 그 기기에만 알린다.
    DeviceRevoked,
    /// 팀 이름이 그 조직의 다른 팀과 겹친다(#355, 관리자 판정 뒤에만).
    NameTaken,
    /// `device.register` 의 아이디를 다른 사람이 쓴다(#364).
    HandleTaken,
    /// 관리자가 0명이 된다(묶음 5) — 다른 관리자를 먼저 세운다.
    LastAdmin,
    /// 사용자 미전달 첨부 합계를 넘는다(묶음 15).
    Quota,
    /// relay 디스크가 하한 아래(묶음 15).
    StorageFull,
    /// 확인되지 않은(잎 자격 없는) 기기가 관리자 동작을 하려 했다(#737).
    DeviceUnconfirmed,
    /// #845 ④ 이 계정이 다른 조직으로 옮겼다 — 곧 닫는다, 앱은 바로 다시 붙는다.
    OrgChanged,
    /// #845 ⑤ 운영 멈춤(인증 뒤, contacts 연결에만).
    AccountSuspended,
    /// #888 이 기기가 방금 확인됐다 — 곧 닫는다, 앱은 바로 다시 붙는다(org_changed 와 같은 길).
    Approved,
}

/// `device.revoked.by`(묶음 5): 누가 끊었나.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RevokedBy {
    /// 본인 기기(자기·내 다른 기기).
    Device,
    /// 조직 관리자(남 기기 끊기·내보내기).
    Admin,
    /// 내가 조직을 나갔다(`member.leave`).
    Left,
    /// 다른 내 기기의 메일 확인 끊기(#577 `device.recover`)가 at 에 끊었다.
    Recovery,
    /// 조직 관리자가 기기 바꾸는 중인 사람의 옛 기기만 끊었다(#737 `member.revoke_device` — 내보내기 아님).
    AdminDevice,
}

impl RevokedBy {
    /// `devices.revoked_by` 에 저장하는 값.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Admin => "admin",
            Self::Left => "left",
            Self::Recovery => "recovery",
            Self::AdminDevice => "admin_device",
        }
    }

    /// 저장된 값. 묶음 5 전에 폐기된 행(NULL)·모르는 값은 `None`.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "device" => Some(Self::Device),
            "admin" => Some(Self::Admin),
            "left" => Some(Self::Left),
            "recovery" => Some(Self::Recovery),
            "admin_device" => Some(Self::AdminDevice),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryPerson {
    pub address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// 폐기되지 않은 기기의 공개키(#132). 수신 코어가 TOFU 로 고정하고 device_id 를 재계산해 대조한다.
    pub devices: Vec<DirectoryDevice>,
    /// 확인한 이메일(hosted, #355 — 같은 조직에만). M1 은 없다.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    /// 고른 팀 id(hosted, #355). M1 은 없다.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub teams: Option<Vec<String>>,
    /// 디렉터리를 받는 사람이 이 사람을 초대했다(M1 결함 ①). 받는 사람마다 계산, 아니면 생략.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_by_me: Option<bool>,
    /// 이 사람이 디렉터리를 받는 사람을 초대했다(§17.3 `invited_by_me` 의 짝). 받는 사람마다 계산, 아니면 생략.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub invited_me: Option<bool>,
    /// 접속 중(묶음 14 B1). 이 사람이나 받는 사람이 숨기면 생략(맞교환).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// 프로필 사진 blob(묶음 15).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// 고른 기본 이미지(#874) — 저장한 정규 JSON 그대로. hello.look 없는 연결엔 [`crate::ws`] 쓰기 고리가 뺀다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub look: Option<Value>,
    /// 증명 있는 폐기(묶음 22 §12-11 ⓐ) — 뿌리 그래프의 고리. 없으면 생략.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub revocations: Vec<DirectoryRevocation>,
    /// 메일 확인 끊기(#577). 걸기가 없으면 생략.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery: Option<DirectoryRecoveryView>,
    /// #845 links 항목에만: 내가 이 연락처에게 task 를 열었다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_ok: Option<bool>,
    /// #845 links 항목에만: 이 연락처가 나에게 task 를 열었다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_ok_for_me: Option<bool>,
    /// 880 3 덧 links 항목에만: 연락처가 된(수락) 시각, RFC 3339.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub linked_at: Option<String>,
    /// #886 ⑧ links 항목에만: 받는 사람의 초대 링크로 이 사람이 들어와 맺어졌다. 아니면 생략.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_my_link: Option<bool>,
}

/// 디렉터리 사람 항목의 `recovery`(#577) — 동료는 state·at·requester 만, 받는 사람 자신은 전부.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryRecoveryView {
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// 막은 기기·시각.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked_by: Option<DirectoryRecoveryBlocker>,
    /// #737 scheduled: 대상(옛 기기)이 붙어서 한 번 미뤘다 — `at` 이 미룬 시각.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub postponed: bool,
}

/// [`DirectoryRecoveryView::blocked_by`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryRecoveryBlocker {
    pub device_id: String,
    pub at: String,
}

/// 증명 있는 폐기 하나(묶음 22 §12-11 ⓐ).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryRevocation {
    pub device_id: String,
    pub added_at: String,
    pub ed25519: String,
    pub x25519: String,
    /// 그 기기로 들어오는 devcert(e73b25bd). 없으면 생략.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certs: Vec<DeviceCert>,
    pub at: String,
    pub signer: String,
    pub sig: String,
}

/// 받는 사람의 조직(hosted, #355).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryOrg {
    pub id: String,
    pub name: String,
    /// 조직 관리자 아이디들(이름순, 묶음 5).
    pub admins: Vec<String>,
    /// 조직 사진 blob(#554). 없으면 생략.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub avatar: Option<String>,
    /// #845 §7-46 덧 4 `personal`(가입 때 만든 개인 공간)·`org`. 화면이 개인 공간인지 아는 길.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    /// 조직 고유색(org.update.color). 없으면 생략.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// #845 둘째 ② 조직 밖 연락 막음(`closed`). 열림이면 생략.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub external_closed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryTeam {
    pub id: String,
    pub name: String,
}

/// 디렉터리 프레임 하나의 내용(#355 — org·teams 는 hosted 만).
#[derive(Debug, Clone, Default)]
pub struct DirectoryBody {
    pub people: Vec<DirectoryPerson>,
    pub sessions: Vec<DirectorySession>,
    pub org: Option<DirectoryOrg>,
    pub teams: Option<Vec<DirectoryTeam>>,
    /// #845 수락된 연락처(조직 밖). contacts 연결이 아니면 쓰기 고리가 뺀다.
    pub links: Option<Vec<DirectoryPerson>>,
    /// #845 걸린 연락 요청. contacts 연결이 아니면 쓰기 고리가 뺀다.
    pub link_requests: Option<LinkRequestsView>,
    /// #845 ④ 받은 조직 초대. contacts 연결이 아니면 쓰기 고리가 뺀다.
    pub org_invites: Option<Vec<OrgInviteView>>,
    /// #845 ④ 받은 그룹 초대. contacts 연결이 아니면 쓰기 고리가 뺀다.
    pub group_invites: Option<Vec<GroupInviteView>>,
    /// #845 §7-26 그 조직이 보낸 초대(관리자에게). contacts 연결이 아니면 쓰기 고리가 뺀다.
    pub org_invites_sent: Option<Vec<SentInviteView>>,
    /// #845 §7-26 내가 보낸 그룹 초대. contacts 연결이 아니면 쓰기 고리가 뺀다.
    pub group_invites_sent: Option<Vec<SentInviteView>>,
    /// #845 ④ 그룹에서만 만나는 사람(주소·이름·기기 키·certs·revocations — §7-14). contacts 연결이 아니면 쓰기 고리가 뺀다.
    pub group_members: Option<Vec<DirectoryPerson>>,
    /// #845 §7-56 내 계정의 음소거한 대화. hello.mutes 연결이 아니면 쓰기 고리가 뺀다.
    pub mutes: Option<Vec<MuteView>>,
    /// #880 내 계정의 고정한 대화(위에서부터). hello.pins 연결이 아니면 쓰기 고리가 뺀다.
    pub pins: Option<Vec<String>>,
    /// #845 둘째 내 친구 목록(주인 자신에게만). 판 16 아래 연결이면 쓰기 고리가 뺀다.
    pub lists: Option<Vec<crate::db::UserList>>,
}

/// #845 §7-56 디렉터리 `mutes` 한 줄(`until` 없음 = 풀 때까지).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MuteView {
    pub conv: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub until: Option<String>,
}

/// #845 §7-26 보낸 초대 한 줄(`group` 은 그룹 초대만).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SentInviteView {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    pub shown: String,
    pub at: String,
}

/// #845 ④ 디렉터리 `group_invites` 한 줄.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GroupInviteView {
    pub id: String,
    pub group: String,
    pub by: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_display: Option<String>,
    pub at: String,
    pub members: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joining: Option<bool>,
}

/// #845 ④ 디렉터리 `org_invites` 한 줄.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct OrgInviteView {
    pub id: String,
    pub org_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub by_display: Option<String>,
    pub at: String,
    /// 받을 수 없음("other_org").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocked: Option<String>,
    /// 그 조직 고유색. 없으면 생략.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub org_color: Option<String>,
}

/// #845 디렉터리 `link_requests`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkRequestsView {
    pub incoming: Vec<LinkIncoming>,
    pub outgoing: Vec<LinkOutgoing>,
}

/// 받은 요청 — 수락 전이라 아바타·기기 없음.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkIncoming {
    pub id: String,
    pub address: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    pub at: String,
}

/// 보낸 요청 — 상대의 것은 아무것도 싣지 않는다(state 도 없음).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LinkOutgoing {
    pub id: String,
    pub to: String,
    pub at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectoryDevice {
    pub device_id: String,
    pub device_pubkeys: DevicePubkeys,
    /// 등록 시각(RFC 3339, #339). 서명하지 않는 메타데이터.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub added_at: Option<String>,
    /// 마지막 접속한 날(UTC 0시, 묶음 22 §12-27 ⓑ). 받는 사람 자신의 기기에만 — 동료 것은 늘 `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_at: Option<String>,
    /// 마지막으로 붙어 있던 시각(ms 정밀도, #577). 받는 사람 자신의 기기에만.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_auth_at: Option<String>,
    /// 지금 붙어 있나(판 15, 모바일 가입 '맥 꺼짐'). 받는 사람 자신의 기기에만 — 판 15 아래 연결엔 [`crate::ws::for_version`] 이 뺀다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub online: Option<bool>,
    /// 마지막 연결이 어떻게 끝났나(#870 — `sleep`·`quit`·`lost`). 받는 사람 자신의, 지금 안 붙은 기기에만 — hello.away
    /// 연결이 아니면 쓰기 고리가 뺀다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub away: Option<String>,
    /// 기기가 알린 OS(판 15, `device.name.os`). 받는 사람 자신의 기기에만 — 판 15 아래 연결엔 뺀다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    /// 내 기기 서명(#393) — 폐기 안 된 서명자의 것만. 없으면 생략.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub certs: Vec<DeviceCert>,
    /// 기기 이름(#490 묶음 28 §4) — 요청한 사람 자신의 항목에만. 없으면 생략.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// 마지막으로 붙은 hello.v(#598 ②). 판 10 이상 연결에만 나간다 — 9 연결엔 [`crate::ws::for_version`] 이 뺀다.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub v: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DeviceCert {
    pub signer: String,
    pub sig: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DevicePubkeys {
    pub ed25519: String,
    pub x25519: String,
    /// `x25519_sig`(#313). #313 전에 등록한 기기는 없다 — 피어는 그런 기기를 버린다.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_sig: Option<String>,
}

/// 세션의 프로젝트(묶음 23 §5 — `{id, name}`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProjectRef {
    pub id: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DirectorySession {
    pub address: String,
    pub grade: String,
    pub liveness: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub folder: Option<String>,
    /// 프로젝트(묶음 23 §5).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub project: Option<ProjectRef>,
    /// 턴 처리 중(A15). 참일 때만 싣는다.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub busy: Option<bool>,
    /// 에이전트 종류(Codex C2). 없으면 claude_code.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// 주인 코어의 같은 이름 번호(관문 Y2, 1..=999).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no: Option<u16>,
    /// #739: dead 인 까닭이 그 기기 끊김(주인 맥 오프라인). 참일 때만.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offline: Option<bool>,
    /// #845 둘째: 주인에게만 — 저장된 공개 범위(users, lists). 범위가 people 일 때만(없으면 조직 전체).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audience: Option<SessionAudience>,
}

/// #845 둘째: 주인 디렉터리의 내 세션 항목 `audience`(ws `Audience` 꼴, kind 는 늘 people).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionAudience {
    pub kind: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub users: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub lists: Vec<String>,
}

/// 서버 → 클라이언트. 직렬화는 [`ServerFrame::to_json`] 이 생성 타입으로 한다.
#[derive(Debug, Clone)]
pub enum ServerFrame {
    Challenge {
        nonce: String,
    },
    Ready {
        server: String,
        now: String,
        pending: u64,
        /// 원격 relay 의 관리자 아이디(#364). 로컬 relay 는 없음.
        /// 내가 관리자인가(원격 relay 만, 묶음 5).
        admin: Option<bool>,
    },
    /// `device.register` 의 응답(#364).
    DeviceRegistered {
        user: String,
        device_id: String,
    },
    Ack {
        msg_id: String,
        /// kind group 이면 서버 순서(묶음 16, snapshot 제외).
        group_seq: Option<u64>,
    },
    Nack {
        msg_id: String,
        reason: NackReason,
    },
    Deliver {
        message: Value,
        /// kind group 의 서버 순서(묶음 16).
        group_seq: Option<u64>,
    },
    Status {
        msg_id: String,
        state: String,
        abort_reason: Option<String>,
        /// `state == failed` 일 때의 사유 코드(#134).
        fail_reason: Option<String>,
        at: String,
        /// 그룹 글에서 읽은·바꾼 사람 주소(묶음 16 §4). 1:1·내 다른 기기면 없음.
        by: Option<String>,
    },
    Directory(DirectoryBody),
    DirectoryUpdate(DirectoryBody),
    /// `invite.create` 의 응답(#355).
    InviteCreated {
        token: String,
        expires_at: String,
    },
    /// `device.revoke` 의 응답(#325). `device_id` 는 요청에 있던 값 그대로(#339). `by` 는 묶음 5.
    DeviceRevoked {
        device_id: Option<String>,
        by: Option<RevokedBy>,
        /// 끊긴 시각(#577, RFC3339).
        at: Option<String>,
    },
    /// 폐기된 기기가 자기 키로 맞게 서명했다(#339) — `error{device_revoked, by}`. `by` 는 묶음 5(모르면 없음).
    Revoked {
        by: Option<RevokedBy>,
        /// 끊긴 시각(#577, `devices.revoked_ms` 의 RFC3339).
        at: Option<String>,
    },
    /// `server.status` 의 응답(묶음 5). 생성 타입 그대로.
    ServerStatus(Box<ws::ServerStatus>),
    /// 생성 타입 그대로(묶음 22 MLS 프레임 — key_packages·low·group_info·commit_final/void·duty·rejoin_needed).
    Ws(Box<ws::Frame>),
    /// `blob.reserve` 의 응답(묶음 15).
    BlobReserved {
        req: String,
        blob_id: String,
        put_token: String,
    },
    /// `groups.list` 의 응답·조직 빠짐 직후·접속 때(묶음 16): (그룹 주소, 마지막 seq, 조직 빠짐으로 나간 (사람 주소, left_seq)).
    Groups(Vec<GroupItem>),
    /// `blob.get` 의 응답(묶음 15).
    BlobTicket {
        req: String,
        blob_id: String,
        get_token: String,
    },
    Ping,
    Pong,
    Error {
        code: ErrorCode,
        message: String,
        r#ref: Option<String>,
    },
}

/// 생성 타입으로 못 바꾸는 값(서버 버그)이면 이 프레임을 대신 보낸다.
const INTERNAL_ERROR_JSON: &str = r#"{"code":"internal","message":"internal","t":"error"}"#;

fn gen_org(o: &DirectoryOrg) -> ws::DirectoryOrg {
    ws::DirectoryOrg {
        admins: o.admins.iter().filter_map(|a| tv(a).ok()).collect(),
        avatar: o.avatar.as_deref().and_then(|a| tv(a).ok()),
        color: o.color.as_deref().and_then(|c| c.parse().ok()),
        external: o.external_closed.then_some(ws::OrgExternal::Closed),
        id: o.id.clone(),
        kind: o.kind.as_deref().map(|k| {
            if k == "personal" {
                ws::DirectoryOrgKind::Personal
            } else {
                ws::DirectoryOrgKind::Org
            }
        }),
        name: o.name.clone(),
    }
}

fn gen_teams(teams: Option<&[DirectoryTeam]>) -> Vec<ws::DirectoryTeam> {
    teams
        .unwrap_or_default()
        .iter()
        .map(|t| ws::DirectoryTeam {
            id: t.id.clone(),
            name: t.name.clone(),
        })
        .collect()
}

/// #845 `link_requests` → 생성 타입.
fn gen_link_requests(r: &LinkRequestsView) -> Result<ws::LinkRequests, String> {
    Ok(ws::LinkRequests {
        incoming: r
            .incoming
            .iter()
            .map(|i| {
                Ok(ws::LinkRequestsIncomingItem {
                    id: tv(&i.id)?,
                    address: tv(&i.address)?,
                    display: i.display.clone(),
                    email: i.email.as_deref().map(tv).transpose()?,
                    at: tv(&i.at)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
        outgoing: r
            .outgoing
            .iter()
            .map(|o| {
                Ok(ws::LinkRequestsOutgoingItem {
                    id: tv(&o.id)?,
                    to: tv(&o.to)?,
                    at: tv(&o.at)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    })
}

/// #845 ④ `org_invites` → 생성 타입.
fn gen_org_invites(v: &[OrgInviteView]) -> Result<ws::OrgInvites, String> {
    Ok(ws::OrgInvites(
        v.iter()
            .map(|i| {
                Ok(ws::OrgInvitesItem {
                    id: tv(&i.id)?,
                    org_name: i.org_name.clone(),
                    by_display: i.by_display.clone(),
                    at: tv(&i.at)?,
                    blocked: i
                        .blocked
                        .as_deref()
                        .map(|b| b.parse().map_err(|_| format!("blocked {b}")))
                        .transpose()?,
                    org_color: i.org_color.as_deref().and_then(|c| c.parse().ok()),
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    ))
}

/// #845 ④ `group_invites` → 생성 타입.
fn gen_group_invites(v: &[GroupInviteView]) -> Result<ws::GroupInvites, String> {
    Ok(ws::GroupInvites(
        v.iter()
            .map(|i| {
                Ok(ws::GroupInvitesItem {
                    id: tv(&i.id)?,
                    group: tv(&i.group)?,
                    by: tv(&i.by)?,
                    by_display: i.by_display.clone(),
                    at: tv(&i.at)?,
                    members: i.members,
                    joining: i.joining,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    ))
}

/// #845 §7-26 `org_invites_sent` → 생성 타입.
fn gen_org_sent(v: &[SentInviteView]) -> Result<ws::OrgInvitesSent, String> {
    Ok(ws::OrgInvitesSent(
        v.iter()
            .map(|i| {
                Ok(ws::OrgInvitesSentItem {
                    id: tv(&i.id)?,
                    shown: tv(&i.shown)?,
                    at: tv(&i.at)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    ))
}

/// #845 §7-26 `group_invites_sent` → 생성 타입.
fn gen_group_sent(v: &[SentInviteView]) -> Result<ws::GroupInvitesSent, String> {
    Ok(ws::GroupInvitesSent(
        v.iter()
            .map(|i| {
                Ok(ws::GroupInvitesSentItem {
                    id: tv(&i.id)?,
                    group: tv(i.group.as_deref().unwrap_or_default())?,
                    shown: tv(&i.shown)?,
                    at: tv(&i.at)?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    ))
}

/// #845 §7-56 `mutes` → 생성 타입.
fn gen_mutes(v: &[MuteView]) -> Result<ws::Mutes, String> {
    Ok(ws::Mutes(
        v.iter()
            .map(|m| {
                Ok(ws::MutesItem {
                    conv: m.conv.clone(),
                    until: m.until.as_deref().map(tv).transpose()?,
                })
            })
            .collect::<Result<Vec<_>, String>>()?,
    ))
}

/// #845 둘째 디렉터리 `lists`.
fn gen_lists(v: &[crate::db::UserList]) -> Result<Vec<ws::FriendList>, String> {
    v.iter()
        .map(|l| {
            Ok(ws::FriendList {
                list_id: tv(&l.list_id)?,
                name: tv(&l.name)?,
                users: l.users.clone(),
            })
        })
        .collect()
}

fn tv<T: TryFrom<String>>(s: &str) -> Result<T, String> {
    T::try_from(s.to_owned()).map_err(|_| format!("형식이 맞지 않는 값: {s}"))
}

/// `groups` 의 한 줄(묶음 16): (그룹 주소, 마지막 seq, 조직 빠짐으로 나간 (사람 주소, left_seq), #845 ④ 들어가는 중인
/// 사람 주소, §7-57 들어가는 중인 사람의 (주소, 가입 표시 이름)).
pub type GroupItem = (
    String,
    u64,
    Vec<(String, u64)>,
    Vec<String>,
    Vec<(String, String)>,
);

impl ServerFrame {
    pub fn to_json(&self) -> String {
        match self.to_value() {
            Ok(v) => v,
            Err(e) => {
                tracing::error!(error = %e, frame = ?self, "생성 타입으로 직렬화 실패 — internal 오류로 대체");
                INTERNAL_ERROR_JSON.to_owned()
            }
        }
    }

    fn to_value(&self) -> Result<String, String> {
        use lodelai_protocol::message::{Grade, PersonAddress, SessionAddress};
        let frame: ws::Frame = match self {
            Self::Challenge { nonce } => ws::Frame::Challenge(ws::Challenge {
                nonce: tv(nonce)?,
                t: ws::ChallengeT::Challenge,
            }),
            Self::Ready {
                server,
                now,
                pending,
                admin,
            } => ws::Frame::Ready(ws::Ready {
                admin: *admin,
                now: tv(now)?,
                pending: *pending,
                server: server.clone(),
                t: ws::ReadyT::Ready,
            }),
            Self::Ack { msg_id, group_seq } => ws::Frame::Ack(ws::Ack {
                group_seq: group_seq.and_then(std::num::NonZeroU64::new),
                msg_id: tv(msg_id)?,
                t: ws::AckT::Ack,
            }),
            Self::Nack { msg_id, reason } => ws::Frame::Nack(ws::Nack {
                msg_id: tv(msg_id)?,
                reason: match reason {
                    NackReason::Auth => ws::NackReason::Auth,
                    NackReason::Unroutable => ws::NackReason::Unroutable,
                    NackReason::TooLarge => ws::NackReason::TooLarge,
                    NackReason::StaleDevices => ws::NackReason::StaleDevices,
                    NackReason::EpochTaken => ws::NackReason::EpochTaken,
                    NackReason::StaleEpoch => ws::NackReason::StaleEpoch,
                    NackReason::InvalidCommit => ws::NackReason::InvalidCommit,
                    NackReason::CommitVoid => ws::NackReason::CommitVoid,
                    NackReason::RateLimited => ws::NackReason::RateLimited,
                    NackReason::BlobUnavailable => ws::NackReason::BlobUnavailable,
                },
                t: ws::NackT::Nack,
            }),
            // 서명이 걸린 원본 JSON 을 그대로 — 타입으로 다시 직렬화하지 않는다.
            Self::Deliver { message, group_seq } => {
                let mut v = serde_json::json!({"t": "deliver", "message": message});
                if let Some(s) = group_seq {
                    v["group_seq"] = serde_json::json!(s);
                }
                return Ok(v.to_string());
            }
            Self::Status {
                msg_id,
                state,
                abort_reason,
                fail_reason,
                at,
                by,
            } => ws::Frame::Status(ws::Status {
                by: match by {
                    Some(b) => Some(tv(b)?),
                    None => None,
                },
                fail_reason: match fail_reason {
                    Some(f) => Some(
                        f.parse::<lodelai_protocol::message::FailReason>()
                            .map_err(|_| format!("fail_reason {f}"))?,
                    ),
                    None => None,
                },
                abort_reason: match abort_reason {
                    Some(a) => Some(
                        lodelai_protocol::states::AbortReason::from_name(a)
                            .ok_or_else(|| format!("abort_reason {a}"))?,
                    ),
                    None => None,
                },
                at: tv(at)?,
                msg_id: tv(msg_id)?,
                state: state
                    .parse::<ws::StatusState>()
                    .map_err(|_| format!("state {state}"))?,
                t: ws::StatusT::Status,
            }),
            Self::Directory(DirectoryBody {
                people,
                sessions,
                org,
                teams,
                links,
                link_requests,
                org_invites,
                group_invites,
                group_members,
                org_invites_sent,
                group_invites_sent,
                mutes,
                pins,
                lists,
            }) => {
                let person = |p: &DirectoryPerson| -> Result<ws::DirectoryPeopleItem, String> {
                    let devices = p
                        .devices
                        .iter()
                        .map(|d| {
                            Ok(ws::DirectoryDevice {
                                device_id: tv(&d.device_id)?,
                                device_pubkeys: ws::DirectoryDeviceDevicePubkeys {
                                    ed25519: tv(&d.device_pubkeys.ed25519)?,
                                    x25519: tv(&d.device_pubkeys.x25519)?,
                                    x25519_sig: d
                                        .device_pubkeys
                                        .x25519_sig
                                        .as_deref()
                                        .map(tv)
                                        .transpose()?,
                                },
                                added_at: d.added_at.as_deref().map(tv).transpose()?,
                                last_auth_at: d.last_auth_at.as_deref().map(tv).transpose()?,
                                online: d.online,
                                away: d.away.as_deref().and_then(|a| a.parse().ok()),
                                os: d.os.as_deref().and_then(|o| o.parse().ok()),
                                last_seen_at: d.last_seen_at.as_deref().map(tv).transpose()?,
                                certs: d
                                    .certs
                                    .iter()
                                    .map(|c| {
                                        Ok(ws::DirectoryDeviceCertsItem {
                                            signer: tv(&c.signer)?,
                                            sig: tv(&c.sig)?,
                                        })
                                    })
                                    .collect::<Result<Vec<_>, String>>()?,
                                name: d.name.as_deref().map(tv).transpose()?,
                                v: d.v,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()?;
                    Ok(ws::DirectoryPeopleItem {
                        recovery: p
                            .recovery
                            .as_ref()
                            .map(|r| -> Result<ws::DirectoryRecovery, String> {
                                Ok(ws::DirectoryRecovery {
                                    at: r.at.as_deref().map(tv).transpose()?,
                                    blocked_by: r
                                        .blocked_by
                                        .as_ref()
                                        .map(|b| -> Result<_, String> {
                                            Ok(ws::DirectoryRecoveryBlockedBy {
                                                at: tv(&b.at)?,
                                                device_id: tv(&b.device_id)?,
                                            })
                                        })
                                        .transpose()?,
                                    postponed: r.postponed.then_some(true),
                                    requester: r.requester.as_deref().map(tv).transpose()?,
                                    state: serde_json::from_value(serde_json::Value::String(
                                        r.state.clone(),
                                    ))
                                    .map_err(|e| e.to_string())?,
                                    targets: r.targets.iter().map(|t| tv(t)).collect::<Result<
                                        Vec<_>,
                                        String,
                                    >>(
                                    )?,
                                })
                            })
                            .transpose()?,
                        address: tv::<PersonAddress>(&p.address)?,
                        devices,
                        display: p.display.clone(),
                        email: p.email.as_deref().map(tv).transpose()?,
                        // 저장은 검사한 값만 — 그래도 읽히지 않으면 그 칸만 버린다(디렉터리 전체를 버리지 않게).
                        look: match p.look.clone() {
                            Some(Value::Object(m)) => m,
                            _ => serde_json::Map::new(),
                        },
                        teams: p.teams.clone().unwrap_or_default(),
                        invited_by_me: p.invited_by_me,
                        invited_me: p.invited_me,
                        online: p.online,
                        revocations: p
                            .revocations
                            .iter()
                            .map(|r| {
                                Ok(ws::DirectoryRevocation {
                                    added_at: tv(&r.added_at)?,
                                    at: tv(&r.at)?,
                                    certs: r
                                        .certs
                                        .iter()
                                        .map(|c| {
                                            Ok(ws::DirectoryRevocationCertsItem {
                                                signer: tv(&c.signer)?,
                                                sig: tv(&c.sig)?,
                                            })
                                        })
                                        .collect::<Result<Vec<_>, String>>()?,
                                    device_id: tv(&r.device_id)?,
                                    ed25519: tv(&r.ed25519)?,
                                    sig: tv(&r.sig)?,
                                    signer: tv(&r.signer)?,
                                    x25519: tv(&r.x25519)?,
                                })
                            })
                            .collect::<Result<Vec<_>, String>>()?,
                        avatar: p.avatar.as_deref().map(tv).transpose()?,
                        task_ok: p.task_ok,
                        task_ok_for_me: p.task_ok_for_me,
                        linked_at: p.linked_at.as_deref().map(tv).transpose()?,
                        joined_my_link: p.joined_my_link,
                    })
                };
                let people = people
                    .iter()
                    .map(person)
                    .collect::<Result<Vec<_>, String>>()?;
                let links = links
                    .as_ref()
                    .map(|l| l.iter().map(person).collect::<Result<Vec<_>, String>>())
                    .transpose()?
                    .unwrap_or_default();
                let link_requests = link_requests.as_ref().map(gen_link_requests).transpose()?;
                let sessions = sessions
                    .iter()
                    .map(|s| {
                        Ok(ws::DirectorySessionsItem {
                            address: tv::<SessionAddress>(&s.address)?,
                            display: s.display.clone(),
                            title: s.title.clone(),
                            folder: s.folder.clone(),
                            project: match &s.project {
                                Some(p) => Some(ws::PublishProject {
                                    id: tv(&p.id)?,
                                    name: tv(&p.name)?,
                                }),
                                None => None,
                            },
                            busy: s.busy,
                            agent: s.agent.as_deref().map(tv).transpose()?,
                            no: s.no.and_then(|n| std::num::NonZeroU64::new(u64::from(n))),
                            offline: s.offline,
                            audience: match &s.audience {
                                Some(a) => Some(ws::Audience {
                                    kind: ws::AudienceKind::People,
                                    users: a
                                        .users
                                        .iter()
                                        .map(|x| tv(x))
                                        .collect::<Result<_, _>>()?,
                                    lists: a
                                        .lists
                                        .iter()
                                        .map(|x| tv(x))
                                        .collect::<Result<_, _>>()?,
                                }),
                                None => None,
                            },
                            grade: match s.grade.as_str() {
                                "question" => Grade::Question,
                                "task" => Grade::Task,
                                g => return Err(format!("grade {g}")),
                            },
                            liveness: match s.liveness.as_str() {
                                "live:channel" => ws::DirectorySessionsItemLiveness::LiveChannel,
                                "live:pty" => ws::DirectorySessionsItemLiveness::LivePty,
                                "dead" => ws::DirectorySessionsItemLiveness::Dead,
                                l => return Err(format!("liveness {l}")),
                            },
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?;
                ws::Frame::Directory(ws::Directory {
                    org: org.as_ref().map(gen_org),
                    people,
                    links,
                    link_requests,
                    org_invites: org_invites.as_deref().map(gen_org_invites).transpose()?,
                    group_invites: group_invites
                        .as_deref()
                        .map(gen_group_invites)
                        .transpose()?,
                    org_invites_sent: org_invites_sent.as_deref().map(gen_org_sent).transpose()?,
                    group_invites_sent: group_invites_sent
                        .as_deref()
                        .map(gen_group_sent)
                        .transpose()?,
                    mutes: mutes.as_deref().map(gen_mutes).transpose()?,
                    pins: pins.clone().map(ws::Pins),
                    lists: lists
                        .as_deref()
                        .map(gen_lists)
                        .transpose()?
                        .unwrap_or_default(),
                    group_members: group_members
                        .as_ref()
                        .map(|l| {
                            l.iter()
                                .map(person)
                                .collect::<Result<Vec<_>, String>>()
                                .map(ws::GroupMembers)
                        })
                        .transpose()?,
                    sessions,
                    t: ws::DirectoryT::Directory,
                    teams: gen_teams(teams.as_deref()),
                })
            }
            Self::DirectoryUpdate(DirectoryBody {
                people,
                sessions,
                org,
                teams,
                links,
                link_requests,
                org_invites,
                group_invites,
                group_members,
                org_invites_sent,
                group_invites_sent,
                mutes,
                pins,
                lists,
            }) => {
                // 스키마가 directory.update 의 항목을 느슨한 객체로 둔다 — directory 와 같은 모양을 Map 으로 싣는다.
                let to_maps = |v: serde_json::Value| -> Vec<serde_json::Map<String, Value>> {
                    v.as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|x| x.as_object().cloned())
                        .collect()
                };
                ws::Frame::DirectoryUpdate(ws::DirectoryUpdate {
                    org: org.as_ref().map(gen_org),
                    teams: gen_teams(teams.as_deref()),
                    people: to_maps(serde_json::to_value(people).map_err(|e| e.to_string())?),
                    sessions: to_maps(serde_json::to_value(sessions).map_err(|e| e.to_string())?),
                    links: to_maps(serde_json::to_value(links).map_err(|e| e.to_string())?),
                    link_requests: link_requests.as_ref().map(gen_link_requests).transpose()?,
                    org_invites: org_invites.as_deref().map(gen_org_invites).transpose()?,
                    group_invites: group_invites
                        .as_deref()
                        .map(gen_group_invites)
                        .transpose()?,
                    org_invites_sent: org_invites_sent.as_deref().map(gen_org_sent).transpose()?,
                    group_invites_sent: group_invites_sent
                        .as_deref()
                        .map(gen_group_sent)
                        .transpose()?,
                    mutes: mutes.as_deref().map(gen_mutes).transpose()?,
                    pins: pins.clone().map(ws::Pins),
                    lists: lists
                        .as_deref()
                        .map(gen_lists)
                        .transpose()?
                        .unwrap_or_default(),
                    group_members: to_maps(
                        serde_json::to_value(group_members).map_err(|e| e.to_string())?,
                    ),
                    t: ws::DirectoryUpdateT::DirectoryUpdate,
                })
            }
            Self::DeviceRevoked { device_id, by, at } => {
                ws::Frame::DeviceRevoked(ws::DeviceRevoked {
                    at: at.as_deref().map(tv).transpose()?,
                    by: by.map(|b| match b {
                        RevokedBy::Device => ws::DeviceRevokedBy::Device,
                        RevokedBy::Admin => ws::DeviceRevokedBy::Admin,
                        RevokedBy::Left => ws::DeviceRevokedBy::Left,
                        RevokedBy::Recovery => ws::DeviceRevokedBy::Recovery,
                        RevokedBy::AdminDevice => ws::DeviceRevokedBy::AdminDevice,
                    }),
                    device_id: device_id.as_deref().map(tv).transpose()?,
                    t: ws::DeviceRevokedT::DeviceRevoked,
                })
            }
            Self::ServerStatus(s) => ws::Frame::ServerStatus((**s).clone()),
            Self::Ws(f) => (**f).clone(),
            Self::Revoked { by, at } => ws::Frame::Error(ws::Error {
                at: at.as_deref().map(tv).transpose()?,
                by: by.map(|b| match b {
                    RevokedBy::Device => ws::ErrorBy::Device,
                    RevokedBy::Admin => ws::ErrorBy::Admin,
                    RevokedBy::Left => ws::ErrorBy::Left,
                    RevokedBy::Recovery => ws::ErrorBy::Recovery,
                    RevokedBy::AdminDevice => ws::ErrorBy::AdminDevice,
                }),
                code: ws::ErrorCode::DeviceRevoked,
                max: None,
                until: None,
                reason: None,
                message: "handshake".into(),
                min: None,
                ref_: None,
                t: ws::ErrorT::Error,
            }),
            Self::InviteCreated { token, expires_at } => {
                ws::Frame::InviteCreated(ws::InviteCreated {
                    expires_at: tv(expires_at)?,
                    t: ws::InviteCreatedT::InviteCreated,
                    token: tv(token)?,
                })
            }
            Self::DeviceRegistered { user, device_id } => {
                ws::Frame::DeviceRegistered(ws::DeviceRegistered {
                    device_id: tv(device_id)?,
                    t: ws::DeviceRegisteredT::DeviceRegistered,
                    user: tv(user)?,
                })
            }
            Self::BlobReserved {
                req,
                blob_id,
                put_token,
            } => ws::Frame::BlobReserved(ws::BlobReserved {
                blob_id: tv(blob_id)?,
                put_token: tv(put_token)?,
                req: tv(req)?,
                t: ws::BlobReservedT::BlobReserved,
            }),
            Self::Groups(items) => ws::Frame::Groups(ws::Groups {
                items: items
                    .iter()
                    .map(|(g, seq, left, joining, names)| {
                        Ok(ws::GroupsItemsItem {
                            group: tv(g)?,
                            seq: *seq,
                            // §7-57 덧 3: 들어가는 중인 사람 전원의 가입 이름(멤버 이름은 디렉터리 group_members 가
                            // 싣는다). 꼴이 맞지 않는 줄(길이 넘침 등)만 건너뛴다 — 비면 칸 없음.
                            members_display: names
                                .iter()
                                .filter_map(|(u, n)| {
                                    Some(ws::GroupsItemsItemMembersDisplayItem {
                                        user: tv(u).ok()?,
                                        display_name: tv(n).ok()?,
                                    })
                                })
                                .collect(),
                            joining: joining
                                .iter()
                                .map(|u| tv(u))
                                .collect::<Result<Vec<_>, String>>()?,
                            org_left: left
                                .iter()
                                .map(|(u, s)| {
                                    Ok(ws::GroupsItemsItemOrgLeftItem {
                                        user: tv(u)?,
                                        seq: *s,
                                    })
                                })
                                .collect::<Result<Vec<_>, String>>()?,
                        })
                    })
                    .collect::<Result<Vec<_>, String>>()?,
                t: ws::GroupsT::Groups,
            }),
            Self::BlobTicket {
                req,
                blob_id,
                get_token,
            } => ws::Frame::BlobTicket(ws::BlobTicket {
                blob_id: tv(blob_id)?,
                get_token: tv(get_token)?,
                req: tv(req)?,
                t: ws::BlobTicketT::BlobTicket,
            }),
            Self::Ping => ws::Frame::Ping(ws::Ping { t: ws::PingT::Ping }),
            Self::Pong => ws::Frame::Pong(ws::Pong { t: ws::PongT::Pong }),
            Self::Error {
                code,
                message,
                r#ref,
            } => ws::Frame::Error(ws::Error {
                at: None,
                code: match code {
                    ErrorCode::RateLimited => ws::ErrorCode::RateLimited,
                    ErrorCode::Protocol => ws::ErrorCode::Protocol,
                    ErrorCode::Internal => ws::ErrorCode::Internal,
                    ErrorCode::TooEarly => ws::ErrorCode::TooEarly,
                    ErrorCode::DeviceRevoked => ws::ErrorCode::DeviceRevoked,
                    ErrorCode::NameTaken => ws::ErrorCode::NameTaken,
                    ErrorCode::HandleTaken => ws::ErrorCode::HandleTaken,
                    ErrorCode::LastAdmin => ws::ErrorCode::LastAdmin,
                    ErrorCode::Quota => ws::ErrorCode::Quota,
                    ErrorCode::StorageFull => ws::ErrorCode::StorageFull,
                    ErrorCode::DeviceUnconfirmed => ws::ErrorCode::DeviceUnconfirmed,
                    ErrorCode::OrgChanged => ws::ErrorCode::OrgChanged,
                    ErrorCode::AccountSuspended => ws::ErrorCode::AccountSuspended,
                    ErrorCode::Approved => ws::ErrorCode::Approved,
                },
                by: None,
                max: None,
                until: None,
                reason: None,
                message: message.clone(),
                min: None,
                ref_: r#ref.clone(),
                t: ws::ErrorT::Error,
            }),
        };
        serde_json::to_string(&frame).map_err(|e| e.to_string())
    }
}

/// 주소 `user@server[/slug]`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Address {
    pub user: String,
    pub server: String,
    pub slug: Option<String>,
}

impl Address {
    /// 그룹 주소 `+<gid>@server`(묶음 16).
    #[must_use]
    pub fn is_group(&self) -> bool {
        self.user.starts_with('+')
    }

    /// 그룹 주소의 gid(소문자 ULID 26자). 그룹 주소가 아니거나 모양이 틀리면 `None`.
    #[must_use]
    pub fn gid(&self) -> Option<&str> {
        let g = self.user.strip_prefix('+')?;
        (g.len() == 26
            && g.bytes()
                .all(|b| b.is_ascii_digit() || b.is_ascii_lowercase()))
        .then_some(g)
    }

    /// §7-56 음소거 대화 열쇠 — 저장(`mute.set`)과 비교(받은 글 머리)가 같은 꼴을 쓰게 한 함수로. 아이디·서버는 소문자,
    /// slug 는 그대로.
    #[must_use]
    pub fn conv_key(&self) -> String {
        let (user, server) = (self.user.to_lowercase(), self.server.to_lowercase());
        match &self.slug {
            Some(slug) => format!("{user}@{server}/{slug}"),
            None => format!("{user}@{server}"),
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let (user, rest) = s.split_once('@')?;
        let (server, slug) = match rest.split_once('/') {
            Some((srv, slug)) => (srv, Some(slug.to_owned())),
            None => (rest, None),
        };
        if user.is_empty() || server.is_empty() || slug.as_deref() == Some("") {
            return None;
        }
        Some(Self {
            user: user.to_owned(),
            server: server.to_owned(),
            slug,
        })
    }
}

/// 메시지 종류.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Chat,
    Request,
    Reply,
    Rejected,
    System,
    /// 묶음 22: pair·self 의 Handshake(start·commit).
    Mls,
    /// 멤버 변경(묶음 16).
    Group,
    /// 이모지 반응(묶음 39 #626) — 본문은 E2E 라 relay 는 'A 가 B(또는 그룹)에게 반응 하나'만 안다.
    Reaction,
    /// 내 기기끼리(#870·#872): 휴대폰이 맥 카드에 누름·그 실패·나에게서 지우기. self 그룹 MLS 만([`Kind::is_own`]).
    OwnControl,
    OwnControlResult,
    OwnDelete,
}

impl Kind {
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "chat" => Self::Chat,
            "request" => Self::Request,
            "reply" => Self::Reply,
            "rejected" => Self::Rejected,
            "system" => Self::System,
            "mls" => Self::Mls,
            "group" => Self::Group,
            "reaction" => Self::Reaction,
            "own_control" => Self::OwnControl,
            "own_control_result" => Self::OwnControlResult,
            "own_delete" => Self::OwnDelete,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Chat => "chat",
            Self::Request => "request",
            Self::Reply => "reply",
            Self::Rejected => "rejected",
            Self::System => "system",
            Self::Mls => "mls",
            Self::Group => "group",
            Self::Reaction => "reaction",
            Self::OwnControl => "own_control",
            Self::OwnControlResult => "own_control_result",
            Self::OwnDelete => "own_delete",
        }
    }

    /// 내 기기끼리만 오가는 글(#870·#872) — 보낸 사용자 = 받는 사용자·self 그룹, 판 `OWN_CONTROL_PROTOCOL` 아래 기기엔
    /// 전하지 않고 푸시하지 않는다.
    pub fn is_own(self) -> bool {
        matches!(
            self,
            Self::OwnControl | Self::OwnControlResult | Self::OwnDelete
        )
    }

    /// `body.text` 상한(UTF-8 바이트, constants.json). `rejected`·`system` 은 500자 — 바이트로는 넉넉히 2000.
    pub fn body_max_bytes(self) -> usize {
        use lodelai_protocol::constants as c;
        match self {
            Self::Request => c::BODY_MAX_BYTES_REQUEST as usize,
            Self::Reply => c::BODY_MAX_BYTES_REPLY as usize,
            Self::Chat => c::BODY_MAX_BYTES_CHAT as usize,
            Self::Rejected | Self::System => c::REASON_MAX_CHARS as usize * 4,
            // Handshake 는 크기를 프레임 상한(과 §5c)이 정한다 — 평문 상한 없음.
            Self::Mls => usize::MAX,
            Self::Group => c::BODY_MAX_BYTES_GROUP as usize,
            Self::Reaction => c::BODY_MAX_BYTES_REACTION as usize,
            Self::OwnControl | Self::OwnControlResult | Self::OwnDelete => {
                c::BODY_MAX_BYTES_OWN as usize
            }
        }
    }
}

/// 서버가 라우팅에 쓰는 헤더. `body` 는 크기만 본다.
#[derive(Debug, Clone)]
pub struct Header {
    pub msg_id: String,
    pub thread_id: String,
    pub reply_to: Option<String>,
    pub kind: Kind,
    pub from: Address,
    pub from_device_id: String,
    pub to: Address,
    pub grade: Option<String>,
    pub created_at: String,
    pub expires_at: String,
    /// 평문 바이트(MLS 응용 메시지는 암호문 − 머리, 평문 system 은 0).
    pub body_bytes: usize,
    /// chat 이 고친 원 메시지(묶음 14 #404).
    pub edits: Option<String>,
    /// system 의 `reason`(묶음 14 #403 — `withdrawn` 만 라우팅이 다르다).
    pub reason: Option<String>,
    /// 본문 `enc: mls`(묶음 22) — 헤더 `mls_group`·`epoch` 와 본문 칸.
    pub mls: Option<MlsHead>,
    /// 묶인 첨부(묶음 15). 형식(1~10·중복 없음·blob_id 모양·kind)은 파싱에서 본다.
    pub blobs: Vec<String>,
    /// 그룹(묶음 16): `to` 가 그룹이면 그 주소, 아니면 헤더 `group`(그룹 안 request·reply·rejected·system).
    pub group: Option<Address>,
    /// kind group 의 변경 종류·대상·기준 seq.
    pub group_op: Option<String>,
    pub subject: Option<Address>,
    /// 만들기 Commit 의 처음 멤버(묶음 22 §12-22) — `group_op: create`·wire commit 일 때만, 그 밖엔 없음.
    pub subjects: Option<Vec<Address>>,
    pub base_seq: Option<u64>,
    /// 메시지 판(9·10 — 쓰는 칸의 판, #598 ②). 10 이면 판 9 기기에 전하지 않는다(recipient_outdated).
    pub v: u64,
}

/// MLS 본문 꼴(묶음 22 §12 — 칸 규칙은 파싱에서 본다). payload 들은 디코드한 MLS 바이트.
#[derive(Debug, Clone)]
pub struct MlsHead {
    pub group: String,
    pub epoch: u64,
    pub wire: MlsWire,
    pub payload: Option<MlsBytes>,
    pub group_info: Option<MlsBytes>,
    pub welcome: Option<MlsBytes>,
}

/// MLS 칸 하나(§5c): 프레임 안 바이트, 또는 ADR 0009 blob 참조(MLS 바이트 그대로 — 받는 쪽이 size·sha256 을 맞춘다).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MlsBytes {
    Data(Vec<u8>),
    Blob {
        blob_id: String,
        size: u64,
        /// base64url(무패딩) SHA-256.
        sha256: String,
    },
}

impl MlsBytes {
    /// 프레임 안 바이트(blob 이면 `None` — relay 가 읽어 [`MlsBytes::Data`] 로 바꾼 뒤 쓴다).
    #[must_use]
    pub fn data(&self) -> Option<&[u8]> {
        match self {
            Self::Data(d) => Some(d),
            Self::Blob { .. } => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MlsWire {
    App,
    Start,
    Commit,
}

/// 응용 메시지 PrivateMessage 의 머리·덧붙임(평문 상한에 더해 받는 몫 — 스파이크 머리 150).
pub const MLS_APP_OVERHEAD: usize = 512;

/// `{data}`(프레임 안) 또는 `{blob:{blob_id, size, sha256}}`(§5c). 그 밖의 꼴은 형식 오류.
fn mls_payload(v: Option<&Value>) -> Option<Option<MlsBytes>> {
    let Some(v) = v else { return Some(None) };
    let o = v.as_object()?;
    if o.len() != 1 {
        return None;
    }
    if let Some(d) = o.get("data") {
        return Some(Some(MlsBytes::Data(
            lodelai_crypto::encoding::decode(d.as_str()?, "mls").ok()?,
        )));
    }
    let b = o.get("blob")?.as_object()?;
    if b.len() != 3 {
        return None;
    }
    let blob_id = b.get("blob_id")?.as_str()?;
    let size = b.get("size")?.as_u64().filter(|n| *n >= 1)?;
    let sha256 = b.get("sha256")?.as_str()?;
    let sha_ok = sha256.len() == 43
        && sha256
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_');
    (is_blob_id(blob_id) && sha_ok).then(|| {
        Some(MlsBytes::Blob {
            blob_id: blob_id.to_owned(),
            size,
            sha256: sha256.to_owned(),
        })
    })
}

/// 본문 `enc: mls` 와 헤더 `mls_group`·`epoch`. 칸 규칙(app = payload, start = group_info, commit = payload + group_info
/// [+ welcome])을 어기면 `None`(형식 오류). kind mls 는 start·commit 만, 그 밖의 kind 는 app 만.
fn parse_mls(kind: Kind, obj: &serde_json::Map<String, Value>, body: &Value) -> Option<MlsHead> {
    let b = body.as_object()?;
    let wire = match b.get("wire")?.as_str()? {
        "app" => MlsWire::App,
        "start" => MlsWire::Start,
        "commit" => MlsWire::Commit,
        _ => return None,
    };
    // kind mls(pair·self Handshake)는 start·commit, kind group 은 셋 다(§12-13 ① — op 마다는 Header 에서), 그 밖은 app.
    let wire_ok = match kind {
        Kind::Mls => wire != MlsWire::App,
        Kind::Group => true,
        _ => wire == MlsWire::App,
    };
    if !wire_ok {
        return None;
    }
    if b.keys().any(|k| {
        !matches!(
            k.as_str(),
            "enc" | "wire" | "payload" | "group_info" | "welcome"
        )
    }) {
        return None;
    }
    let payload = mls_payload(b.get("payload"))?;
    let group_info = mls_payload(b.get("group_info"))?;
    let welcome = mls_payload(b.get("welcome"))?;
    let shape_ok = match wire {
        // 응용 메시지는 평문 상한 안이라 프레임 안({data})만.
        MlsWire::App => {
            payload.as_ref().is_some_and(|p| p.data().is_some())
                && group_info.is_none()
                && welcome.is_none()
        }
        MlsWire::Start => payload.is_none() && group_info.is_some() && welcome.is_none(),
        MlsWire::Commit => payload.is_some() && group_info.is_some(),
    };
    let group = obj.get("mls_group")?.as_str()?.to_owned();
    let gid_ok = (group.len() == 43
        && group
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_'))
        || (group.len() == 26
            && group
                .bytes()
                .all(|c| c.is_ascii_digit() || c.is_ascii_lowercase()));
    let epoch = obj.get("epoch")?.as_u64()?;
    (shape_ok && gid_ok).then_some(MlsHead {
        group,
        epoch,
        wire,
        payload,
        group_info,
        welcome,
    })
}

/// MLS 응용 메시지 평문의 JSON 머리 고정분(§12-17).
pub const MLS_PLAINTEXT_HEAD_BYTES: usize = 64;

impl Header {
    /// 평문 상한(UTF-8 바이트). MLS 면 kind 상한 + 머리 고정분 + `FILE_ENTRY_MAX_BYTES` × 첨부 수(ADR 0009 §3).
    #[must_use]
    pub fn body_max_bytes(&self) -> usize {
        // enc mls 는 pt 가 없다 — 평문은 'JSON 머리 한 줄 + \n + 본문 원 바이트'라 머리 고정분 + 헤더 blobs 개수로(§12-17).
        let files = lodelai_protocol::constants::FILE_ENTRY_MAX_BYTES as usize * self.blobs.len();
        let extra = if self.mls.is_some() {
            MLS_PLAINTEXT_HEAD_BYTES + files
        } else {
            0
        };
        self.kind.body_max_bytes().saturating_add(extra)
    }
}

/// 첨부 blob id 모양(무작위 128비트 base64url 무패딩 22자).
#[must_use]
pub fn is_blob_id(s: &str) -> bool {
    s.len() == 22
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

impl Header {
    /// 필수 필드가 없거나 형식이 틀리면 `None`(프로토콜 위반).
    pub fn from_value(m: &Value) -> Option<Self> {
        let obj = m.as_object()?;
        let s = |k: &str| obj.get(k).and_then(Value::as_str).map(str::to_owned);
        let kind = Kind::parse(&s("kind")?)?;
        let from_obj = obj.get("from")?.as_object()?;
        let from = Address::parse(from_obj.get("address")?.as_str()?)?;
        let from_device_id = from_obj.get("device_id")?.as_str()?.to_owned();
        // from.verbatim(묶음 14)은 author=human + assisted_by 일 때만, 값은 true 만.
        if let Some(v) = from_obj.get("verbatim") {
            if v.as_bool() != Some(true)
                || from_obj.get("author").and_then(Value::as_str) != Some("human")
                || !from_obj.contains_key("assisted_by")
            {
                return None;
            }
        }
        let to = Address::parse(obj.get("to")?.get("address")?.as_str()?)?;
        let body = obj.get("body")?;
        let mut mls = None;
        let body_bytes = match body.get("enc").and_then(Value::as_str) {
            // 묶음 22: MLS — 응용 메시지는 암호문 길이 − 머리를 평문 상한에 견준다. Handshake 는 프레임 상한.
            Some("mls") => {
                let m = parse_mls(kind, obj, body)?;
                let n = match m.wire {
                    MlsWire::App => m
                        .payload
                        .as_ref()
                        .and_then(MlsBytes::data)
                        .map_or(0, |p| p.len().saturating_sub(MLS_APP_OVERHEAD)),
                    _ => 0,
                };
                mls = Some(m);
                n
            }
            _ if kind == Kind::Mls => return None,
            // v1 평문은 system 빈 본문뿐(e2e-envelope §3.4) — 그 밖의 평문은 형식 오류(다운그레이드 방지).
            Some("plain") => {
                let text = body.get("text")?.as_str()?;
                if kind != Kind::System || !text.is_empty() {
                    return None;
                }
                0
            }
            // 묶음 22: 봉투(`enc: box`, #313)는 받지 않는다(#503) — 1:1 도 MLS. 모르는 enc 와 같은 형식 오류.
            _ => return None,
        };
        // 첨부(묶음 15): chat·request·reply 만, 1~FILES_PER_MESSAGE·중복 없음·blob_id 모양. 그 밖은 형식 오류.
        let blobs: Vec<String> = match obj.get("blobs") {
            None => Vec::new(),
            Some(v) => {
                let ids: Vec<String> = v
                    .as_array()?
                    .iter()
                    .map(|b| b.as_str().filter(|s| is_blob_id(s)).map(str::to_owned))
                    .collect::<Option<_>>()?;
                let unique: std::collections::HashSet<&String> = ids.iter().collect();
                if !matches!(kind, Kind::Chat | Kind::Request | Kind::Reply)
                    || ids.is_empty()
                    || ids.len() > lodelai_protocol::constants::FILES_PER_MESSAGE as usize
                    || unique.len() != ids.len()
                {
                    return None;
                }
                ids
            }
        };
        // 그룹(묶음 16) 모양: 보낸 사람은 그룹일 수 없고, 헤더 group 은 그룹 주소이며 to 가 그룹이면 같아야 한다. to 가 그룹이면
        // chat·group·system 만, 헤더 group 이 따로 붙는 것은 request·reply·rejected·system 만. kind group 은 to 가 그룹이고 봉투이며
        // group_op 에 맞는 subject 와 base_seq 가 있어야 한다.
        if from.is_group() {
            return None;
        }
        let header_group = match obj.get("group") {
            None => None,
            Some(g) => Some(Address::parse(g.as_str()?).filter(|a| a.gid().is_some())?),
        };
        if to.is_group() && to.gid().is_none() {
            return None;
        }
        let group = if to.is_group() {
            if header_group.as_ref().is_some_and(|g| *g != to)
                || !matches!(
                    kind,
                    Kind::Chat | Kind::Group | Kind::System | Kind::Reaction
                )
            {
                return None;
            }
            Some(to.clone())
        } else {
            if header_group.is_some()
                && !matches!(
                    kind,
                    Kind::Request | Kind::Reply | Kind::Rejected | Kind::System
                )
            {
                return None;
            }
            header_group
        };
        let group_op = s("group_op");
        let subject = match obj.get("subject") {
            None => None,
            Some(v) => {
                Some(Address::parse(v.as_str()?).filter(|a| !a.is_group() && a.slug.is_none())?)
            }
        };
        let subjects = match obj.get("subjects") {
            None => None,
            Some(v) => Some(
                v.as_array()?
                    .iter()
                    .map(|x| {
                        Address::parse(x.as_str()?).filter(|a| !a.is_group() && a.slug.is_none())
                    })
                    .collect::<Option<Vec<_>>>()?,
            ),
        };
        let base_seq = obj.get("base_seq").map(Value::as_u64);
        // 그룹 맥락(to 그룹·헤더 group·kind group)은 enc mls 만 — 판 7 은 box 와 같이 쓰지 않는다(§12-13 ⑤).
        if (group.is_some() || kind == Kind::Group) && mls.is_none() {
            return None;
        }
        if kind == Kind::Group {
            // op ↔ wire(§12-13 ①②): create = start, 트리를 바꾸는 op = commit, leave 는 나가는 사람의 app 또는 남은 기기의
            // commit, rename 은 app(§12-23 — 이름은 MLS 평문 안). snapshot 은 없다.
            let wire = mls.as_ref()?.wire;
            // create 는 start(만든 사람 혼자) 뒤 첫 Commit 이 처음 멤버를 subjects 로 한꺼번에(§12-22) — subjects 는 그 Commit 만.
            let creating_commit = group_op.as_deref() == Some("create") && wire == MlsWire::Commit;
            if creating_commit != subjects.is_some() || subjects.as_ref().is_some_and(Vec::is_empty)
            {
                return None;
            }
            let (needs_subject, wire_ok) = match group_op.as_deref()? {
                "create" => (false, wire != MlsWire::App),
                "add" | "remove" | "admin" | "org_left" => (true, wire == MlsWire::Commit),
                "leave" => (true, wire != MlsWire::Start),
                "rename" => (false, wire == MlsWire::App),
                // 사람 op 가 아닌 Commit(주기 Update·새 기기 Add·폐기 잎 Remove·복구, §12-15).
                "update" => (false, wire == MlsWire::Commit),
                _ => return None,
            };
            if !to.is_group()
                || !wire_ok
                || needs_subject != subject.is_some()
                || base_seq.flatten().is_none()
            {
                return None;
            }
        } else if group_op.is_some()
            || subject.is_some()
            || subjects.is_some()
            || base_seq.is_some()
        {
            return None;
        }
        let base_seq = base_seq.flatten();
        // 다른 버전(v0 평문 등)은 받지 않는다(#313 — 다운그레이드 방지). 9·10 이 함께 돈다(#598 ② — 메시지 v 는 쓰는 칸의 판, 판 11 은 연결 판일 뿐 — #613 MESSAGE_V_MAX).
        let v = obj.get("v").and_then(Value::as_u64)?;
        if !(u64::from(lodelai_protocol::PROTOCOL_MIN)..=u64::from(lodelai_protocol::MESSAGE_V_MAX))
            .contains(&v)
        {
            return None;
        }
        if kind == Kind::Reaction && v < lodelai_protocol::constants::REACTION_V {
            return None;
        }
        // #845 §7-50 request 의 reply_to(이어서 묻기)는 판 REQUEST_REPLY_V 칸 — 그 아래 v 에 실리면 형식 오류(reaction 과 같은 꼴).
        if kind == Kind::Request
            && obj.get("reply_to").is_some()
            && v < lodelai_protocol::constants::REQUEST_REPLY_V
        {
            return None;
        }
        // no_reply(#598 ②)는 request 의 판 10 칸 — 값은 true 만, v 는 10 이상(스키마 if/then 을 typify 가 못 받아 여기서 본다).
        if let Some(n) = obj.get("no_reply") {
            if n.as_bool() != Some(true) || kind != Kind::Request || v < 10 {
                return None;
            }
        }
        Some(Self {
            msg_id: s("msg_id")?,
            thread_id: s("thread_id")?,
            reply_to: s("reply_to"),
            kind,
            from,
            from_device_id,
            to,
            grade: s("grade"),
            created_at: s("created_at")?,
            expires_at: s("expires_at")?,
            body_bytes,
            edits: s("edits"),
            reason: s("reason"),
            v,
            mls,
            blobs,
            group,
            group_op,
            subject,
            subjects,
            base_seq,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn address_parse() {
        let a = Address::parse("dana@local/frontend").unwrap();
        assert_eq!(
            (a.user.as_str(), a.server.as_str(), a.slug.as_deref()),
            ("dana", "local", Some("frontend"))
        );
        let p = Address::parse("bo@local").unwrap();
        assert!(p.slug.is_none());
        assert!(Address::parse("nouser").is_none());
        assert!(Address::parse("@local").is_none());
        assert!(Address::parse("dana@local/").is_none());
    }

    #[test]
    fn verbatim_은_사람_assisted_by_일_때만() {
        let msg = |from: Value| {
            serde_json::json!({
                "v": lodelai_protocol::MESSAGE_V_MAX, "msg_id": "01JB00000000000000000000V1",
                "thread_id": "01JB00000000000000000000V1", "kind": "system", "from": from,
                "to": {"address": "kim@local"}, "body": {"enc": "plain", "text": ""},
                "created_at": "2026-10-26T00:00:00.000Z", "expires_at": "2026-11-02T00:00:00.000Z",
            })
        };
        let d = "k1_AAAAAAAAAAAAAAAAAAAAAA";
        let ok = serde_json::json!({"address": "dana@local", "author": "human",
            "assisted_by": "dana@local/api", "verbatim": true, "device_id": d});
        assert!(Header::from_value(&msg(ok)).is_some());
        for bad in [
            serde_json::json!({"address": "dana@local", "author": "human", "verbatim": true, "device_id": d}),
            serde_json::json!({"address": "dana@local/api", "author": "agent", "session_id": "s",
                "assisted_by": "dana@local/api", "verbatim": true, "device_id": d}),
            serde_json::json!({"address": "dana@local", "author": "human",
                "assisted_by": "dana@local/api", "verbatim": false, "device_id": d}),
        ] {
            assert!(Header::from_value(&msg(bad.clone())).is_none(), "{bad}");
        }
    }

    /// #626: reaction 은 판 12 이상·사람 또는 그룹 주소·첨부 없음. 그룹 주소로도 간다.
    #[test]
    fn reaction_은_판_12_부터_그룹에도() {
        let rv = lodelai_protocol::constants::REACTION_V;
        let gid = "01jb00000000000000000000g1";
        let msg = |v: u64, to: &str, extra: Value| {
            let mut m = serde_json::json!({
                "v": v, "msg_id": "01JB00000000000000000000R1", "thread_id": "01JB00000000000000000000R1",
                "kind": "reaction",
                "from": {"address": "dana@local", "author": "human", "device_id": "k1_AAAAAAAAAAAAAAAAAAAAAA"},
                "to": {"address": to}, "mls_group": gid, "epoch": 1,
                "body": {"enc": "mls", "wire": "app", "payload": {"data": "AAAA"}},
                "created_at": "2026-10-26T00:00:00.000Z", "expires_at": "2026-11-02T00:00:00.000Z",
            });
            for (k, x) in extra.as_object().unwrap() {
                m[k] = x.clone();
            }
            m
        };
        let group = format!("+{gid}@local");
        let h = Header::from_value(&msg(rv, "kim@local", serde_json::json!({}))).unwrap();
        assert_eq!(h.kind, Kind::Reaction);
        assert!(Header::from_value(&msg(rv, &group, serde_json::json!({}))).is_some());
        assert!(Header::from_value(&msg(rv - 1, "kim@local", serde_json::json!({}))).is_none());
        let blobs = serde_json::json!({"blobs": ["AAAAAAAAAAAAAAAAAAAAAA"]});
        assert!(Header::from_value(&msg(rv, "kim@local", blobs)).is_none());
    }

    #[test]
    fn frames_round_trip() {
        let f = ClientFrame::parse(
            r#"{"t":"hello","v":9,"device_id":"k1_AAAAAAAAAAAAAAAAAAAAAA","user":"dana"}"#,
        )
        .unwrap();
        assert!(matches!(f, ClientFrame::Hello { v: 9, .. }));
        assert!(matches!(
            ClientFrame::parse(r#"{"t":"directory.list"}"#),
            Some(ClientFrame::DirectoryList)
        ));
        // 스키마 위반: 틀린 device_id 패턴, 모르는 필드, 서버 전용 프레임, 모르는 t
        assert!(
            ClientFrame::parse(r#"{"t":"hello","v":9,"device_id":"k1x","user":"dana"}"#).is_none()
        );
        assert!(ClientFrame::parse(r#"{"t":"ping","extra":1}"#).is_none());
        assert!(
            ClientFrame::parse(r#"{"t":"ack","msg_id":"01JB0000000000000000000001"}"#).is_none()
        );
        assert!(ClientFrame::parse(r#"{"t":"nope"}"#).is_none());
        assert_eq!(
            ServerFrame::Nack {
                msg_id: "01JB0000000000000000000001".into(),
                reason: NackReason::Unroutable
            }
            .to_json(),
            r#"{"msg_id":"01JB0000000000000000000001","reason":"unroutable","t":"nack"}"#
        );
        assert_eq!(
            ServerFrame::Status {
                msg_id: "01JB0000000000000000000001".into(),
                state: "received".into(),
                abort_reason: None,
                fail_reason: None,
                at: "2026-10-23T04:12:56.000Z".into(),
                by: None
            }
            .to_json(),
            r#"{"at":"2026-10-23T04:12:56.000Z","msg_id":"01JB0000000000000000000001","state":"received","t":"status"}"#
        );
        // 생성 타입에 맞지 않는 값(빈 시각 — #118 리뷰 메모)은 빈 at 을 내보내지 않고 internal 오류로 바뀐다
        assert_eq!(
            ServerFrame::Status {
                msg_id: "01JB0000000000000000000001".into(),
                state: "received".into(),
                abort_reason: None,
                fail_reason: None,
                at: String::new(),
                by: None
            }
            .to_json(),
            INTERNAL_ERROR_JSON
        );
    }
}
