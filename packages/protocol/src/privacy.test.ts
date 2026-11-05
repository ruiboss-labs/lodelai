// QA(#355 묶음 5): 내 동료 목록·신뢰 상태·차단 목록은 서버로 나가지 않는다 — 앱이 서버로 보내는 프레임(ws.schema.json)에
// 그런 필드가 없고, 보내는 필드는 아래 목록과 정확히 같다(필드를 더하면 이 시험이 깨져 리뷰를 강제한다).
import { expect, test } from 'bun:test'
import schema from '../schema/ws.schema.json'

type Def = { properties?: { t?: { const?: string } } & Record<string, unknown> }
const defs = schema.$defs as Record<string, Def>

/** 앱 → 서버 프레임(서버가 앱으로만 보내는 deliver·ready·challenge·directory*·error·nack·ack·device.revoked·invite.created 제외). */
const CLIENT_SENT: Record<string, string[]> = {
  hello: ['device_id', 'user', 'v'],
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
  'profile.update': ['avatar', 'display_name', 'teams'],
  'device.revoke': ['device_id', 'proof'],
  'device.certify': ['device_id', 'sig'],
  // #577 메일 확인 끊기 — 칸 없음(누가·무엇은 인증된 연결로 relay 가 안다).
  'device.recover': [],
  'device.recover_cancel': [],
  'device.recover_block': [],
  // name(#490 묶음 28 §4): 그 맥의 컴퓨터 이름 — relay 는 내 사용자 항목에만 싣고 동료에게 보내지 않는다(처리방침 주석).
  'device.name': ['name'],
  'presence.set': ['share'],
  // 입력 중 표시(#613): 쓰는 대화 주소와 켜짐 — 저장하지 않는 평문 메타(security.md 메타 줄). S→C 같은 이름(from·group·on)은 서버가 채운다.
  typing: ['on', 'to'],
  // for(#554): 'org' 이면 조직 사진 — 관리자 검사에만 쓴다(사진은 서버가 보는 메타데이터, 처리방침 줄은 #473).
  'blob.reserve': ['ct_len', 'for', 'purpose', 'req'],
  'blob.get': ['blob_id', 'req'],
  'blob.fetched': ['blob_id'],
  'groups.list': [],
  'groups.replay': ['from_seq', 'group'],
  // avatar(#554): null 만 — 조직 사진 지우기.
  'org.update': ['avatar', 'name'],
  'team.create': ['name'],
  'team.update': ['id', 'name'],
  'team.delete': ['id'],
  'invite.create': ['email'],
  'device.register': ['code'],
  'org.admin': ['admin', 'user'],
  'member.remove': ['user'],
  'member.revoke_device': ['device_id', 'user'],
  'member.leave': [],
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
  for (const t of Object.keys(CLIENT_SENT)) {
    for (const f of fields(byT(t) as Def)) expect(banned.test(f), `${t}.${f}`).toBe(false)
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
  ])
  const all = Object.values(defs).flatMap((d) => (d.properties?.t?.const ? [d.properties.t.const] : []))
  for (const t of all) expect(t in CLIENT_SENT || serverOnly.has(t), `${t}: 방향 미정`).toBe(true)
})
