/**
 * TS 프로토콜 타입 생성(선 스키마만, U1 #52). 레포 루트의 `bun run protocol:gen` 이 Rust 생성기 다음에 부른다.
 * `schema/{message,ws,states}.schema.json` → `src/generated/<name>.ts`, `schema/constants.json` → `src/generated/constants.ts`.
 * 부품은 `gen-lib.ts`.
 */
import { join } from 'node:path'
import { genConstants, generate } from './gen-lib.ts'

const root = join(import.meta.dir, '..')
const schemaDir = join(root, 'schema')
const generator = 'packages/protocol/scripts/gen.ts'
const n = await generate({
  schemaDir,
  outDir: join(root, 'src', 'generated'),
  schemas: ['message', 'ws', 'states'],
  constants: genConstants(schemaDir, ['constants.json'], generator),
  generator,
})
console.log(`protocol gen (ts): ${n} 파일`)
