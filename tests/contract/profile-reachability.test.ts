import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'bun:test'
import { parse } from 'yaml'
import { evaluatePermission } from '../../src/policy/permissions'
import { ExecutionProfile } from '../../src/schema/execution'

/**
 * A matching `deny` always wins, so a `*`-method catch-all silently denies the
 * profile's own `auto` rules. Nothing shipped or generated may have that shape:
 * every declared `auto` route must actually resolve to `auto`.
 */

const REPO = Bun.fileURLToPath(new URL('../..', import.meta.url))

function profilesUnder(prefix: string): { file: string; profile: ExecutionProfile }[] {
  const glob = new Bun.Glob('**/*.yaml')
  return [...glob.scanSync({ cwd: join(REPO, prefix) })].sort().map((relative) => ({
    file: `${prefix}/${relative}`,
    profile: ExecutionProfile.parse(parse(readFileSync(join(REPO, prefix, relative), 'utf8'))),
  }))
}

/** A concrete path a pattern matches, so the rule can be evaluated for real. */
function concretePath(pattern: string): string {
  const segments = pattern
    .slice(1)
    .split('/')
    .filter((segment) => segment !== '**')
    .map((segment) => (segment === '*' ? 'x' : segment))
  return `/${[...segments, ...(pattern.endsWith('/**') ? ['y'] : [])].join('/')}`
}

const GROUPS = [
  ['the starter example catalog', 'examples/starter/catalog/execution'],
  ['the search benchmark fixture catalog', 'tests/fixtures/search/catalog/execution'],
] as const

describe.each(GROUPS)('%s', (_label, prefix) => {
  const entries = profilesUnder(prefix)

  test('has profiles to check', () => {
    expect(entries.length).toBeGreaterThan(0)
  })

  test('every declared auto route resolves to auto', () => {
    const denied: string[] = []
    for (const { file, profile } of entries) {
      for (const rule of profile.permissions) {
        if (rule.decision !== 'auto') continue
        const method = rule.method === '*' ? 'GET' : rule.method
        const outcome = evaluatePermission(profile, method, concretePath(rule.path))
        if (outcome.decision !== 'auto') {
          denied.push(`${file}: ${method} ${rule.path} resolves to ${outcome.decision}`)
        }
      }
    }
    expect(denied).toEqual([])
  })

  test('no profile declares a wildcard-method catch-all deny', () => {
    const offenders = entries
      .filter(({ profile }) =>
        profile.permissions.some(
          (rule) => rule.method === '*' && rule.path === '/**' && rule.decision === 'deny',
        ),
      )
      .map(({ file }) => file)
    expect(offenders).toEqual([])
  })

  test('every profile declaring a health probe can reach it', () => {
    const unreachable: string[] = []
    for (const { file, profile } of entries) {
      const probe = profile.health_probe
      if (!probe) continue
      const outcome = evaluatePermission(profile, probe.method, probe.path)
      // `verify` always confirms, so a probe may be `auto` or `confirm` — never denied.
      if (outcome.decision === 'deny') {
        unreachable.push(`${file}: probe ${probe.method} ${probe.path} is denied`)
      }
    }
    expect(unreachable).toEqual([])
  })

  test('a mutating method is still denied outright', () => {
    const readOnly = entries.filter(({ profile }) =>
      profile.permissions.some((rule) => rule.decision === 'deny'),
    )
    expect(readOnly.length).toBeGreaterThan(0)
    for (const { file, profile } of readOnly) {
      const denies = profile.permissions.filter((rule) => rule.decision === 'deny')
      for (const rule of denies) {
        const method = rule.method === '*' ? 'GET' : rule.method
        const outcome = evaluatePermission(profile, method, concretePath(rule.path))
        expect(`${file}:${outcome.decision}`).toBe(`${file}:deny`)
      }
    }
  })
})

describe('the generators produce reachable profiles', () => {
  test('a wildcard-method catch-all deny appears in no source module', async () => {
    const root = join(REPO, 'src')
    for await (const relative of new Bun.Glob('**/*.ts').scan(root)) {
      const text = await Bun.file(join(root, relative)).text()
      const offending = /method:\s*'\*',\s*path:\s*'\/\*\*',\s*decision:\s*'deny'/.test(text)
      expect(`${relative}:${offending}`).toBe(`${relative}:false`)
    }
  })
})
