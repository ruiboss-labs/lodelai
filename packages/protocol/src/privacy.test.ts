// QA(#355 묶음 5): 내 동료 목록·신뢰 상태·차단 목록은 서버로 나가지 않는다 — 앱이 서버로 보내는 프레임(ws.schema.json)에
// 그런 필드가 없고, 보내는 필드는 아래 목록과 정확히 같다(필드를 더하면 이 시험이 깨져 리뷰를 강제한다).
import { expect, test } from 'bun:test'
import schema from '../schema/ws.schema.json'

type Def = { properties?: { t?: { const?: string } } & Record<string, unknown> }
const defs = schema.$defs as Record<string, Def>

/** 앱 → 서버 프레임(서버가 앱으로만 보내는 deliver·ready·challenge·directory*·error·nack·ack·device.revoked·invite.created 제외). */
const CLIENT_SENT: Record<string, string[]> = {
  // no_duty(모바일 검증): 이 연결이 duty 후보가 아님 — 참/거짓 하나. own(#870): 내 기기끼리 글을 앎 — 참/거짓 하나.
  // look(#874): 디렉터리 look 을 앎 — 참/거짓 하나. contacts(#845): link.*·디렉터리 links 를 앎 — 참/거짓 하나(목록 아님).
  hello: [
    'away',
    'blocks',
    'contacts',
    'device_id',
    'look',
    'mutes',
    'next_turn',
    'no_duty',
    'own',
    'pins',
    'user',
    'v',
  ],
  auth: ['sig'],
  send: ['message'],
  // unreadable(0.2.6 #809): 이 기기가 그 글을 열지 못함 — 참/거짓 하나, 내용·까닭 코드 아님.
  delivered_ack: ['msg_id', 'unreadable'],
  // by: S→C 만(묶음 16 §4, status 정의를 같이 써서 목록에 보임) — 앱은 싣지 않고, 실으면 relay 가 error{protocol}.
  status: ['abort_reason', 'at', 'by', 'fail_reason', 'msg_id', 'state'],
  // audience(묶음 20): 그 세션에 요청할 수 있는 사람 — 라우팅에 필요해 relay 로 간다(다른 사람에게는 싣지 않음, 계약 §2).
  // project(묶음 23 §5): 프로젝트 id·구분 이름(전체 경로 아님) — 동료 화면에서 세션을 프로젝트로 묶는다.
  // agent(Codex C2): 그 세션을 띄운 에이전트 종류(codex 등, 사용자 정보 아님) — 동료 화면 이름 앞 마크.
  // no(관문 Y2): 같은 이름 세션 번호(1..=999, 주인 화면의 'a #6' 의 6) — 내용·경로 아님, 동료 화면 이름 뒤 번호.
  'session.publish': [
    'agent',
    'audience',
    'busy',
    'capabilities',
    'display',
    'folder',
    'grade',
    'liveness',
    'no',
    'project',
    'slug',
    'title',
  ],
  'session.unpublish': ['slug'],
  'directory.list': [],
  // avatar: 사진 지우기(null)만 — 묶음 15 B9, 프로필 사진은 조직 안 공개(처리방침 '정식 릴리스 판' 주석).
  // look(#874): 고른 기본 이미지 — 캐릭터 seed(무작위, 신원과 안 묶임) 또는 색 번호뿐.
  'profile.update': ['avatar', 'display_name', 'look', 'teams'],
  'device.revoke': ['device_id', 'proof'],
  'device.certify': ['device_id', 'sig'],
  // #577 메일 확인 끊기 — 칸 없음(누가·무엇은 인증된 연결로 relay 가 안다).
  'device.recover': [],
  'device.recover_cancel': [],
  'device.recover_block': [],
  // name(#490 묶음 28 §4): 그 맥의 컴퓨터 이름 — relay 는 내 사용자 항목에만 싣고 동료에게 보내지 않는다(처리방침 주석).
  'device.name': ['name', 'os'],
  'presence.set': ['share'],
  // 입력 중 표시(#613): 쓰는 대화 주소와 켜짐 — 저장하지 않는 평문 메타(security.md 메타 줄). S→C 같은 이름(from·group·on)은 서버가 채운다.
  typing: ['on', 'to'],
  // #870: 내 기기 하나에 흘림 — 받는 내 기기·암호문(relay 는 속을 모름)·짝 맞춤 번호뿐. 승인 기다림 알림은 알림 종류(#890 card·
  // usage — 고정 문구를 고르는 데만, 에이전트·숫자 없음)뿐.
  own_stream: ['data', 'epoch', 'seq', 'to_device'],
  own_alert: ['kind'],
  // #882(ADR 0014): 맥의 내 에이전트 합 — 처리 중·승인·질문 수와 가장 오래된 시작 시각뿐(이름·글·폴더 없음, relay 는 메모리에만).
  own_live: ['approval', 'busy', 'oldest', 'question'],
  // #845 연락처(조직 밖 1:1): 이 기기의 동료 칸 목록과 다른 relay 쪽 관계다 — 사람이 요청·수락한 것만 relay 가 쥐고(라우팅에
  // 필요), 두 사람에게만 보인다(설계 #845 §3·§4). 찾기는 정확한 이메일·아이디 하나, 목록을 올리는 프레임은 없다.
  'link.request': ['email', 'req', 'user'],
  'link.answer': ['answer', 'id'],
  'link.remove': ['block', 'peer'],
  'link.update': ['peer', 'task_ok'],
  'link.withdraw': ['id'],
  // 관문 A6 막은 사람 풀기: 그 사람 하나 — 차단 목록을 올리는 프레임은 없다.
  'link.unblock': ['peer', 'req'],
  // #923 §11 사람 막기: 그 사람 하나 — 차단 목록을 올리는 프레임은 없다(목록은 relay 가 디렉터리 blocked 로 주인에게만 준다).
  'link.block': ['peer', 'req'],
  // #923 신고: 신고자가 스스로 고른 글의 평문(ADR 0009 의 유일한 예외) — relay 는 그 자리에서 운영 메일로 보내고 남기지 않는다.
  // 상대는 신고 대상 한 사람, 그룹은 그 신고가 나온 대화 하나. 동료·차단 목록은 없다.
  report: ['group', 'messages', 'note', 'peer', 'reason', 'req'],
  // 내 초대 링크(§7-1): 토큰 하나 — 받는 사람 정보는 없다.
  'contact_link.get': ['req'],
  'contact_link.rotate': ['req'],
  'link.join': ['req', 'token'],
  // §7-23 연락처 링크 미리보기: 토큰 하나(답은 같은 t 의 서버 정의).
  'contact_link.preview': ['req', 'token'],
  // #845 ④ 이메일 초대(§7-2): 관리자·그룹 멤버가 친 이메일·아이디 하나, 받은 초대에 답 — 목록 없음.
  'org.invite': ['email', 'req'],
  'org.invite.answer': ['answer', 'id', 'req'],
  // §7-56 계정 단위 음소거: 대화 주소·기한 하나.
  'mute.set': ['conv', 'req', 'until'],
  'list.put': ['list_id', 'name', 'req', 'users'],
  'list.delete': ['list_id', 'req'],
  'pin.set': ['conv', 'index', 'req'],
  'org.code.check': ['code', 'req'],
  'org.external.preview': ['req'],
  'org.join': ['code', 'req', 'teams'],
  'org.create': ['name', 'req', 'setup_code'],
  'group.invite': ['email', 'group', 'req', 'user'],
  'group.invite.answer': ['answer', 'id', 'req'],
  // §7-26 보낸 초대 거두기: id 하나.
  'org.invite.withdraw': ['id'],
  'group.invite.withdraw': ['id'],
  // for(#554): 'org' 이면 조직 사진 — 관리자 검사에만 쓴다(사진은 서버가 보는 메타데이터, 처리방침 줄은 #473).
  'blob.reserve': ['ct_len', 'for', 'for_device', 'purpose', 'req'],
  'blob.get': ['blob_id', 'req'],
  'blob.fetched': ['blob_id'],
  'groups.list': [],
  'groups.replay': ['from_seq', 'group'],
  // avatar(#554): null 만 — 조직 사진 지우기.
  'org.update': ['avatar', 'color', 'external', 'name'],
  'team.create': ['name'],
  'team.update': ['id', 'name'],
  'team.delete': ['id'],
  'invite.create': ['email'],
  'device.register': ['code'],
  'org.admin': ['admin', 'user'],
  'member.remove': ['user'],
  'member.revoke_device': ['device_id', 'user'],
  'member.leave': [],
  // #877 묶음 B: 조직만 나가고 계정은 남김 — 칸 없음.
  'org.leave': [],
  'server.status': [],
  ping: [],
  pong: [],
  // 묶음 22 MLS — KeyPackage·GroupInfo·2단계 확정(ack·fail 은 기기의 처리 결과만, 동료·신뢰 목록 없음).
  // reset(0.2.5 g025f B): 데이터를 잃은 기기의 첫 올리기 — 그 기기 자신의 옛 KeyPackage 를 바꾼다(동료 정보 없음).
  'key_packages.publish': ['items', 'last_resort', 'reset'],
  'key_packages.claim': ['device_ids'],
  'group_info.get': ['group'],
  commit_ack: ['commit_hash', 'epoch', 'group'],
  commit_fail: ['commit_hash', 'epoch', 'group'],
  // 모바일 검증(시험 relay 만): 이 기기의 OS 푸시 토큰·앱 ID — relay 가 APNs·FCM 으로 보내는 데만 쓴다(정식 판 때 처리방침 항목).
  'push.register': ['app_id', 'env', 'off', 'platform', 'req', 'token'],
  'push.unregister': ['req'],
  // #882(ADR 0014): 이 기기의 현황 받기와 Live Activity 토큰(애플에 보내는 데만) — 숫자·이름 없음.
  'push.live': ['activity', 'on', 'req', 'start_token'],
}

const byT = (t: string): Def | undefined => Object.values(defs).find((d) => d.properties?.t?.const === t)
const fields = (d: Def) =>
  Object.keys(d.properties ?? {})
    .filter((k) => k !== 't')
    .sort()

test('앱이 보내는 프레임의 필드는 정해진 목록과 같다', () => {
  for (const [t, want] of Object.entries(CLIENT_SENT)) {
    const d = byT(t)
    expect(d, `${t} 프레임 정의 없음`).toBeDefined()
    // ack·nack 처럼 서버가 보내기도 하는 이름이 아니라 앱이 보내는 정의만 본다.
    expect(fields(d as Def), t).toEqual(want)
  }
})

test('앱이 보내는 프레임에 동료·신뢰·차단·연락처 필드가 없다', () => {
  const banned = /peer|trust|contact|friend|block|roster|동료/i
  // #845: relay 쪽 연락처 프레임이 상대 한 사람을 가리키는 칸, 빼면서 막기(참/거짓), hello 의 기능 표시(참/거짓). 목록이 아니다 — 위 목록의 주석.
  const relayLinks = new Set([
    'hello.contacts',
    'link.remove.block',
    'link.remove.peer',
    'link.update.peer',
    'link.unblock.peer',
    'link.block.peer',
    'report.peer',
    'hello.blocks',
  ])
  for (const t of Object.keys(CLIENT_SENT)) {
    for (const f of fields(byT(t) as Def)) {
      if (relayLinks.has(`${t}.${f}`)) continue
      expect(banned.test(f), `${t}.${f}`).toBe(false)
    }
  }
})

test('앱이 보내는 프레임 이름이 정의와 어긋나지 않는다 — 새 프레임은 목록에 올려야 한다', () => {
  // 서버가 앱으로만 보내는 프레임. 여기에도 앱 → 서버 목록에도 없는 이름이 생기면 방향을 정하라는 뜻.
  const serverOnly = new Set([
    'challenge',
    'ready',
    'ack',
    'nack',
    'deliver',
    'device.revoked',
    'directory',
    'directory.update',
    'error',
    'invite.created',
    'device.registered',
    'key_packages.low',
    'key_packages',
    'group_info',
    'commit_final',
    'commit_void',
    'group_alert',
    'duty',
    'rejoin_needed',
    'blob.reserved',
    'blob.ticket',
    'groups',
    'device.recover_scheduled',
    'device.recover_canceled',
    'device.recover_against',
    'device.recover_against_ended',
    'device.recovered',
    'push.ok',
    'push.live.ok',
    'own_live.want',
    'link.sent',
    'report.sent',
    'contact_link',
    'org.invite.sent',
    'group.invite.sent',
  ])
  const all = Object.values(defs).flatMap((d) => (d.properties?.t?.const ? [d.properties.t.const] : []))
  for (const t of all) expect(t in CLIENT_SENT || serverOnly.has(t), `${t}: 방향 미정`).toBe(true)
})
