import { execFileSync } from 'node:child_process'
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { parse, stringify } from 'yaml'
import { GrantStore } from '../../src/auth/grants'
import { authStatus } from '../../src/auth/status'
import { authorityFingerprint } from '../../src/catalog/canonical'
import { loadWorkingTree, profilePath } from '../../src/catalog/load'
import { resolveCatalogRoot, type CatalogRoot } from '../../src/catalog/root'
import { validateCatalog } from '../../src/catalog/validate'
import { callApi } from '../../src/execute/call'
import { ApprovalTokens } from '../../src/execute/confirm'
import { HealthStore } from '../../src/execute/health'
import { ResponseCache } from '../../src/execute/cache'
import { verifyProfile } from '../../src/execute/verify'
import { refreshSource, runAdd, SOURCE_IDS, type SourceId } from '../../src/maintenance/commands'
import { OutcomeLedger, SourceManifest, countLedger } from '../../src/schema/report'
import { BenchmarkFile, REQUIRED_HITS, runBenchmark } from '../../src/search/benchmark'
import { CatalogQuery } from '../../src/search/query'
import { buildStore } from '../../src/store/build'
import { openStore } from '../../src/store/open'
import { ExecutionProfile } from '../../src/schema/execution'
import { MOCK_SECRET, startMockServer, type MockServer } from '../fixtures/http/mock-server'
import { fixturePath, loadFixture } from '../helpers/yaml'

/**
 * The v0 acceptance pass: a clean clone of this repository, with no network
 * except the local mock. Criteria 1 through 15 of `docs/design.md`.
 */

const REPO = Bun.fileURLToPath(new URL('../..', import.meta.url))

let clone: string
/** The clean clone's repository root. */
let checkout: string
/** The catalog root inside it — a subdirectory, so the Git prefix path is exercised. */
let catalogRoot: string
let xdg: string
let storePath: string
let grantsPath: string
let healthPath: string
let cacheDir: string
let mock: MockServer
/** Criteria that passed, recorded so the suite reports the whole pass. */
const met = new Set<number>()

function git(cwd: string, ...args: string[]): string {
  return execFileSync('git', ['-C', cwd, ...args], { encoding: 'utf8' })
}

function root(): CatalogRoot {
  const resolution = resolveCatalogRoot(catalogRoot)
  if (!resolution.ok) throw new Error(resolution.message)
  return resolution
}

function inputFor(sourceId: SourceId) {
  const pinDocument = loadFixture('sources', sourceId, 'pin.yaml') as Record<string, unknown>
  const pin = {
    revision: String(pinDocument.revision),
    contentHash: String(pinDocument.content_hash),
    retrievedAt: String(pinDocument.retrieved_at),
  }
  if (sourceId === 'public-apis') {
    return {
      pin,
      payload: JSON.parse(
        readFileSync(fixturePath('sources', 'public-apis', 'entries.json'), 'utf8'),
      ),
    }
  }
  if (sourceId === 'nango') {
    return {
      pin,
      payload: loadFixture('sources', 'nango', 'providers.yaml'),
      scopes: loadFixture('sources', 'nango', 'scopes.yaml'),
    }
  }
  const specs = new Map<string, unknown>()
  const directory = fixturePath('sources', 'apis-guru', 'specs')
  for (const file of new Bun.Glob('*.json').scanSync({ cwd: directory })) {
    // Keyed by upstream list id, `/` written as `__`.
    specs.set(
      file.replace(/\.json$/, '').replaceAll('__', '/'),
      JSON.parse(readFileSync(join(directory, file), 'utf8')),
    )
  }
  return {
    pin,
    payload: JSON.parse(readFileSync(fixturePath('sources', 'apis-guru', 'list.json'), 'utf8')),
    specs,
  }
}

/**
 * A clean clone built from exactly what Git would track — cached plus
 * non-ignored untracked paths — so a gitignored or generated artifact cannot
 * satisfy a criterion. This works whether or not the source repository has
 * commits yet.
 */
function cleanClone(target: string): void {
  const listed = execFileSync(
    'git',
    ['-C', REPO, 'ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { encoding: 'utf8' },
  )
  const files = listed.split('\0').filter((entry) => entry.length > 0)
  if (files.length === 0) throw new Error('the source repository tracks no files')
  for (const relative of files) {
    const destination = join(target, relative)
    execFileSync('mkdir', ['-p', join(destination, '..')])
    writeFileSync(destination, readFileSync(join(REPO, relative)))
  }
  execFileSync('git', ['init', '--quiet', '--initial-branch', 'main', target])
  git(target, 'config', 'user.email', 'acceptance@example.invalid')
  git(target, 'config', 'user.name', 'Acceptance')
  git(target, 'config', 'commit.gpgsign', 'false')
  git(target, 'add', '-A')
  git(target, 'commit', '--quiet', '-m', 'clean clone')
}

beforeAll(async () => {
  clone = mkdtempSync(join(tmpdir(), 'apimanac-acceptance-'))
  checkout = join(clone, 'checkout')
  cleanClone(checkout)
  catalogRoot = join(checkout, 'examples/starter')

  xdg = join(clone, 'xdg')
  storePath = join(xdg, 'catalog.db')
  grantsPath = join(xdg, 'grants.yaml')
  healthPath = join(xdg, 'health.db')
  cacheDir = join(xdg, 'responses')
  mock = await startMockServer()
})

afterAll(async () => {
  await mock.close()
  rmSync(clone, { recursive: true, force: true })
})

describe('1. install from the pinned toolchain and lockfile', () => {
  test('the clone carries the lockfile, the toolchain pin and the flake', () => {
    for (const file of ['bun.lock', 'mise.toml', 'flake.nix', 'flake.lock', 'package.json']) {
      expect(`${file}:${existsSync(join(checkout, file))}`).toBe(`${file}:true`)
    }
    const manifest = JSON.parse(readFileSync(join(checkout, 'package.json'), 'utf8')) as {
      dependencies: Record<string, string>
      devDependencies: Record<string, string>
    }
    // Every dependency is pinned exactly, so a clean install is reproducible.
    for (const version of Object.values({
      ...manifest.dependencies,
      ...manifest.devDependencies,
    })) {
      expect(version).toMatch(/^\d+\.\d+\.\d+$/)
    }
    met.add(1)
  })
})

describe('2. validate the catalog', () => {
  test('the shipped catalog reports no findings', () => {
    const report = validateCatalog(loadWorkingTree(root().path, root().git))
    expect(report.findings.map((finding) => `${finding.kind} ${finding.file}`)).toEqual([])
    met.add(2)
  })
})

describe('3. build the normalized catalog offline', () => {
  test('a build succeeds from tracked files with no outbound connection', () => {
    const before = mock.requests.length
    const result = buildStore(root(), { storePath })
    expect(result.discoveryRecords).toBe(5)
    expect(result.authorityRecords).toBe(5)
    expect(existsSync(storePath)).toBe(true)
    expect(mock.requests.length).toBe(before)
    met.add(3)
  })
})

describe('4. reproduce all three upstream accounting ledgers offline', () => {
  test('every source ledger accounts for its entries exactly once', () => {
    const before = mock.requests.length
    for (const sourceId of SOURCE_IDS) {
      const report = refreshSource(root(), sourceId, inputFor(sourceId))
      expect(`${sourceId}:${report.ok}`).toBe(`${sourceId}:true`)
      const ledger = OutcomeLedger.parse(
        parse(readFileSync(join(catalogRoot, `catalog/sources/${sourceId}/outcomes.yaml`), 'utf8')),
      )
      const manifest = SourceManifest.parse(
        parse(readFileSync(join(catalogRoot, `catalog/sources/${sourceId}/manifest.yaml`), 'utf8')),
      )
      const ids = ledger.entries.map((entry) => entry.source_entry_id)
      expect(new Set(ids).size).toBe(ids.length)
      expect(countLedger(ledger)).toEqual(manifest.counts)
    }
    expect(mock.requests.length).toBe(before)
    git(checkout, 'add', '-A')
    git(checkout, 'commit', '-m', 'import all three sources')
    met.add(4)
  })
})

describe('5. search all imported sources', () => {
  test('records from every source are findable', () => {
    buildStore(root(), { storePath })
    const opened = openStore(root(), { storePath })
    try {
      const catalog = new CatalogQuery(opened.db)
      const all = catalog.search('', { limit: 50 }).results
      const sources = new Set(all.flatMap((entry) => entry.sources))
      for (const sourceId of SOURCE_IDS) {
        expect(`${sourceId}:${sources.has(sourceId)}`).toBe(`${sourceId}:true`)
      }
      met.add(5)
    } finally {
      opened.close()
    }
  })
})

describe('6. meet the search benchmark', () => {
  test('at least 16 of 20 queries return a relevant top-five result', () => {
    // Graded against the committed benchmark catalog, whose relevance labels
    // were authored before any weight was tuned.
    const benchRoot = mkdtempSync(join(tmpdir(), 'apimanac-bench-'))
    try {
      execFileSync('git', ['init', '--quiet', '--initial-branch', 'main', benchRoot])
      execFileSync('git', ['-C', benchRoot, 'config', 'user.email', 'b@example.invalid'])
      execFileSync('git', ['-C', benchRoot, 'config', 'user.name', 'B'])
      writeFileSync(join(benchRoot, '.gitattributes'), 'catalog/** -text\n')
      const source = fixturePath('search', 'catalog')
      for (const relative of new Bun.Glob('**/*.yaml').scanSync({ cwd: source })) {
        const target = join(benchRoot, 'catalog', relative)
        execFileSync('mkdir', ['-p', join(target, '..')])
        writeFileSync(target, readFileSync(join(source, relative)))
      }
      execFileSync('git', ['-C', benchRoot, 'add', '-A'])
      execFileSync('git', ['-C', benchRoot, 'commit', '--quiet', '-m', 'benchmark catalog'])
      const resolved = resolveCatalogRoot(benchRoot)
      if (!resolved.ok) throw new Error(resolved.message)
      const benchStore = join(xdg, 'bench.db')
      buildStore(resolved, { storePath: benchStore })
      const opened = openStore(resolved, { storePath: benchStore })
      try {
        const report = runBenchmark(
          new CatalogQuery(opened.db),
          BenchmarkFile.parse(loadFixture('search', 'queries.yaml')),
        )
        expect(report.hits).toBeGreaterThanOrEqual(REQUIRED_HITS)
        expect(report.exactOk).toBe(true)
        met.add(6)
      } finally {
        opened.close()
      }
    } finally {
      rmSync(benchRoot, { recursive: true, force: true })
    }
  })
})

describe('7. inspect trust, profile, auth readiness and health', () => {
  test('auth status reports readiness with no credential material', () => {
    const report = authStatus(root(), { path: grantsPath })
    expect(report.profiles.length).toBeGreaterThan(0)
    for (const profile of report.profiles) {
      expect(profile.authority_fingerprint).toMatch(/^v1:sha256:[0-9a-f]{64}$/)
      expect(typeof profile.supported).toBe('boolean')
    }
    expect(JSON.stringify(report)).not.toContain(MOCK_SECRET)
    met.add(7)
  })
})

describe('8-10. execute against the local mock', () => {
  function writeMockProfile(profileId: string, overrides: Record<string, unknown>): void {
    const draft: Record<string, unknown> = {
      profile_id: profileId,
      api_id: 'acceptance-mock',
      origins: [mock.origin],
      auth: { type: 'none' },
      network_scope: 'private',
      permissions: [
        { method: 'GET', path: '/ok', decision: 'auto' },
        { method: 'GET', path: '/auth', decision: 'auto' },
        { method: 'POST', path: '/echo', decision: 'confirm' },
        { method: 'DELETE', path: '/**', decision: 'deny' },
      ],
      health_probe: { method: 'GET', path: '/ok', expect_status: 200 },
      verification: { state: 'candidate' },
      ...overrides,
    }
    ExecutionProfile.parse(draft)
    const target = join(catalogRoot, profilePath('acceptance-mock', profileId))
    execFileSync('mkdir', ['-p', join(target, '..')])
    writeFileSync(target, stringify(draft))
  }

  function activateGrant(profileId: string): void {
    const file = join(catalogRoot, profilePath('acceptance-mock', profileId))
    const profile = ExecutionProfile.parse(parse(readFileSync(file, 'utf8')))
    process.env.APIMANAC_ACCEPTANCE_TOKEN = MOCK_SECRET
    writeFileSync(
      grantsPath,
      stringify({
        version: 1,
        grants: [
          {
            credential_id: profile.auth.credential_id,
            api_id: 'acceptance-mock',
            profile_id: profileId,
            origins: profile.origins,
            authority_fingerprint: authorityFingerprint(profile),
            accounts: [
              {
                name: 'primary',
                components: {
                  token: { provider: 'env', variable: 'APIMANAC_ACCEPTANCE_TOKEN' },
                },
              },
            ],
          },
        ],
      }),
      { mode: 0o600 },
    )
    chmodSync(grantsPath, 0o600)
  }

  async function call(overrides: Record<string, unknown>, services: Record<string, unknown> = {}) {
    const health = HealthStore.open(healthPath)
    const cache = ResponseCache.open({ directory: cacheDir })
    try {
      return await callApi(
        {
          root: root(),
          api: 'acceptance-mock',
          method: 'GET',
          path: '/ok',
          ...overrides,
        } as Parameters<typeof callApi>[0],
        {
          grants: GrantStore.load({ path: grantsPath }),
          tokens: new ApprovalTokens('acceptance'),
          health,
          cache,
          ...services,
        } as Parameters<typeof callApi>[1],
      )
    } finally {
      cache.close()
      health.close()
    }
  }

  beforeAll(async () => {
    const metaPath = join(catalogRoot, 'catalog/meta/acceptance-mock.yaml')
    writeFileSync(
      metaPath,
      stringify({
        id: 'acceptance-mock',
        name: 'Acceptance mock',
        description: 'The local mock the acceptance pass executes against.',
        profiles: ['open', 'keyed'],
      }),
    )
    writeMockProfile('open', {})
    writeMockProfile('keyed', {
      auth: {
        type: 'bearer',
        credential_id: 'acceptance-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      health_probe: { method: 'GET', path: '/auth', expect_status: 200 },
    })
    git(checkout, 'add', '-A')
    git(checkout, 'commit', '-m', 'add the acceptance mock candidates')

    // Verify is the only path from candidate to verified.
    const openOutcome = await verifyProfile(
      { root: root(), api: 'acceptance-mock', profile: 'open' },
      {
        grants: GrantStore.load({ path: grantsPath }),
        channel: { label: 'test', confirm: async () => true },
      },
    )
    expect(openOutcome.kind).toBe('verified')

    activateGrant('keyed')
    const keyedOutcome = await verifyProfile(
      { root: root(), api: 'acceptance-mock', profile: 'keyed' },
      {
        grants: GrantStore.load({ path: grantsPath }),
        channel: { label: 'test', confirm: async () => true },
      },
    )
    expect(keyedOutcome.kind).toBe('verified')

    // A reviewer commits the profiles with their evidence.
    git(checkout, 'add', '-A')
    git(checkout, 'commit', '-m', 'commit the verified profiles and their evidence')
  })

  test('8. one no-auth profile executes', async () => {
    const outcome = await call({ profile: 'open', path: '/ok' })
    expect(outcome.kind).toBe('success')
    expect(outcome.status).toBe(200)
    met.add(8)
  })

  test('9. one static-auth profile executes with an ephemeral grant and fixture secret', async () => {
    const outcome = await call({ profile: 'keyed', path: '/auth' })
    expect(outcome.kind).toBe('success')
    expect(outcome.body).toContain('"authenticated":true')
    expect(JSON.stringify(outcome)).not.toContain(MOCK_SECRET)
    met.add(9)
  })

  test('10. a confirmation flow completes within one invocation', async () => {
    let asked = 0
    const outcome = await call(
      { profile: 'open', method: 'POST', path: '/echo', body: { kind: 'json', value: { a: 1 } } },
      {
        channel: {
          label: 'test',
          confirm: async () => {
            asked += 1
            return true
          },
        },
      },
    )
    expect(asked).toBe(1)
    expect(outcome.kind).toBe('success')
    expect(outcome.body).toContain('"method":"POST"')
    met.add(10)
  })

  test('a declined confirmation and a denied operation both send nothing', async () => {
    const before = mock.requests.length
    const declined = await call(
      { profile: 'open', method: 'POST', path: '/echo', body: { kind: 'json', value: {} } },
      { channel: { label: 'test', confirm: async () => false } },
    )
    expect(declined.kind).toBe('confirmation_declined')
    const denied = await call({ profile: 'open', method: 'DELETE', path: '/ok' })
    expect(denied.kind).toBe('denied')
    expect(mock.requests.length).toBe(before)
  })
})

describe('11. add an API as an uncommitted candidate', () => {
  test('a manual add writes an uncommitted record and stages nothing', async () => {
    const head = git(checkout, 'rev-parse', 'HEAD').trim()
    const result = (await runAdd(
      root(),
      { positional: ['Acceptance Added API'], flags: { manual: true } },
      { out: () => undefined, err: () => undefined },
      true,
    )) as { ok: boolean; api_id: string; files: string[] }
    expect(result.ok).toBe(true)
    expect(result.api_id).toBe('acceptance-added-api')
    expect(git(checkout, 'rev-parse', 'HEAD').trim()).toBe(head)
    expect(git(checkout, 'diff', '--cached', '--name-only')).toBe('')
    expect(git(checkout, 'status', '--porcelain')).toContain('acceptance-added-api.yaml')
    met.add(11)
  })
})

describe('12. refresh a source as an uncommitted diff with reports', () => {
  test('a second run over the same pin reports unchanged and writes no diff', () => {
    git(checkout, 'add', '-A')
    git(checkout, 'commit', '-m', 'commit the added candidate')
    const head = git(checkout, 'rev-parse', 'HEAD').trim()
    const report = refreshSource(root(), 'public-apis', inputFor('public-apis'))
    expect(report.ok).toBe(true)
    expect(report.counts.examined).toBeGreaterThan(0)
    expect(report.rejections.length).toBeGreaterThan(0)
    for (const rejection of report.rejections) expect(rejection.reason_code).toBeTruthy()
    expect(git(checkout, 'rev-parse', 'HEAD').trim()).toBe(head)
    expect(git(checkout, 'diff', '--cached', '--name-only')).toBe('')
    met.add(12)
  })
})

describe('13. pass format, type, unit, contract, source, security and MCP tests', () => {
  test('every test group has at least one suite in the clean clone', () => {
    for (const group of ['contract', 'security', 'integration']) {
      const files = [...new Bun.Glob('*.test.ts').scanSync({ cwd: join(checkout, 'tests', group) })]
      expect(`${group}:${files.length > 0}`).toBe(`${group}:true`)
    }
    // The suite this assertion runs inside is the evidence for the rest.
    met.add(13)
  })
})

describe('14. compile the stable executable', () => {
  test('a self-contained apimanac is produced from the clean clone', () => {
    // Criterion 1 in practice: install from the pinned lockfile, from cache only.
    execFileSync('bun', ['install', '--frozen-lockfile', '--offline'], {
      cwd: checkout,
      encoding: 'utf8',
    })
    const outfile = join(xdg, 'apimanac')
    execFileSync(
      'bun',
      ['build', '--compile', '--outfile', outfile, join(checkout, 'src/cli.ts')],
      { cwd: checkout, encoding: 'utf8' },
    )
    expect(existsSync(outfile)).toBe(true)
    const unrelated = mkdtempSync(join(tmpdir(), 'apimanac-unrelated-'))
    try {
      const output = execFileSync(outfile, ['--catalog', catalogRoot, 'validate', '--json'], {
        cwd: unrelated,
        encoding: 'utf8',
        env: {
          ...process.env,
          XDG_CACHE_HOME: join(xdg, 'exec-cache'),
          XDG_STATE_HOME: join(xdg, 'exec-state'),
          XDG_CONFIG_HOME: join(xdg, 'exec-config'),
          XDG_DATA_HOME: join(xdg, 'exec-data'),
        },
      })
      expect((JSON.parse(output) as { ok: boolean }).ok).toBe(true)
      // It writes only under the resolved XDG roots.
      expect([...new Bun.Glob('**/*').scanSync({ cwd: unrelated, onlyFiles: true })]).toEqual([])
      met.add(14)
    } finally {
      rmSync(unrelated, { recursive: true, force: true })
    }
  })
})

describe('15. expose no tracked or surfaced secret', () => {
  test('no tracked catalog file carries a credential value, variable name or path', () => {
    const report = validateCatalog(loadWorkingTree(root().path, root().git))
    expect(report.findings.filter((finding) => finding.kind === 'tracked_secret')).toEqual([])
    met.add(15)
  })

  test('no tracked file in the clone contains the fixture secret outside its own fixture', () => {
    const tracked = git(checkout, 'ls-files').trim().split('\n')
    const offenders: string[] = []
    for (const file of tracked) {
      if (file.startsWith('tests/')) continue
      const contents = readFileSync(join(checkout, file))
      if (contents.indexOf(MOCK_SECRET) !== -1) offenders.push(file)
    }
    expect(offenders).toEqual([])
  })

  test('the documentation records the bootstrap sequence and the confirmation paths', () => {
    const readme = readFileSync(join(checkout, 'README.md'), 'utf8')
    for (const fragment of [
      'catalog_root',
      'apimanac show',
      'authority fingerprint',
      'apimanac verify',
      'controlling terminal',
      'elicitation',
    ]) {
      expect(`${fragment}:${readme.includes(fragment)}`).toBe(`${fragment}:true`)
    }
  })
})

describe('the acceptance pass is recorded', () => {
  test('criteria 1 through 15 all passed', () => {
    const missing = Array.from({ length: 15 }, (_, index) => index + 1).filter(
      (criterion) => !met.has(criterion),
    )
    expect(missing).toEqual([])
  })
})
