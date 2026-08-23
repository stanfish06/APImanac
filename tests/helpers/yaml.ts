import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse } from 'yaml'

export const FIXTURE_ROOT = Bun.fileURLToPath(new URL('../fixtures', import.meta.url))

export function fixturePath(...parts: string[]): string {
  return join(FIXTURE_ROOT, ...parts)
}

export function loadFixture(...parts: string[]): unknown {
  return parse(readFileSync(fixturePath(...parts), 'utf8'))
}
