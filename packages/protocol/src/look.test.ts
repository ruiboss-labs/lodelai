/**
 * #874 §8: 프로필 기본 이미지 꼴(Look)은 ws.schema 가 정본이고 ui.schema 는 그 복사본이다 — 하나만 고치는 일을 막는다.
 */
import { expect, test } from 'bun:test'
import ui from '../schema/ui.schema.json'
import ws from '../schema/ws.schema.json'

test('ui.schema Look 은 ws.schema Look 과 같다', () => {
  expect(ui.$defs.Look).toEqual(ws.$defs.Look)
})
