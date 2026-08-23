import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { parse, stringify } from 'yaml'
import { GrantStore } from '../../src/auth/grants'
import { injectedProvider } from '../../src/auth/providers'
import { authorityFingerprint, contractHash } from '../../src/catalog/canonical'
import { loadCommitted, loadWorkingTree, metadataPath, profilePath } from '../../src/catalog/load'
import { resolveCatalogRoot } from '../../src/catalog/root'
import { committedProfilesFor, evaluateEligibility } from '../../src/policy/eligibility'
import { GrantsFile } from '../../src/schema/grant'
import { ExecutionProfile } from '../../src/schema/execution'
import { migrateCatalog, runAdd } from '../../src/maintenance/commands'
import { resetXdgForTests } from '../../src/paths'
import { CatalogQuery } from '../../src/search/query'
import { buildStore } from '../../src/store/build'
import { openStore } from '../../src/store/open'
import { openRoot, starterCatalogRepo } from '../helpers/catalog'
import { TempRepo, fixtureManifest } from '../helpers/repo'

/**
 * One test per hole a code review found. Each of these passed — or was absent —
 * while the defect it covers was live.
 */

const SECRET = 'fixture-secret-value-0123456789'
const io = { out: () => undefined, err: () => undefined }

let scratch: string

beforeEach(() => {
  scratch = mkdtempSync(join(tmpdir(), 'apimanac-regress-'))
})

afterEach(() => {
  rmSync(scratch, { recursive: true, force: true })
  resetXdgForTests()
})

function bearerProfile(overrides: Record<string, unknown> = {}) {
  return ExecutionProfile.parse({
    profile_id: 'pat',
    api_id: 'example',
    origins: ['https://api.example.com'],
    auth: {
      type: 'bearer',
      credential_id: 'example-token',
      components: [{ name: 'token' }],
      placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
    },
    ...overrides,
  })
}

describe('grant resolution cannot reach a grant readiness rejected', () => {
  const profile = bearerProfile()
  const fingerprint = authorityFingerprint(profile)

  function grantsWith(grants: unknown[], values: Record<string, string>) {
    const path = join(scratch, 'grants.yaml')
    writeFileSync(path, stringify({ version: 1, grants }), { mode: 0o600 })
    return GrantStore.load({ path, provider: injectedProvider(values) })
  }

  const grant = (fp: string, variable: string) => ({
    credential_id: 'example-token',
    api_id: 'example',
    profile_id: 'pat',
    origins: profile.origins,
    authority_fingerprint: fp,
    accounts: [{ name: 'personal', components: { token: { provider: 'env', variable } } }],
  })

  test('a stale grant listed first does not supply the credential', () => {
    // The README workflow leaves the old grant in place after a rebinding, and
    // both grants use the same account name.
    const store = grantsWith(
      [grant(`v1:sha256:${'a'.repeat(64)}`, 'STALE'), grant(fingerprint, 'CURRENT')],
      { token: SECRET },
    )
    expect(store.readinessFor(profile, fingerprint).readiness).toBe('ready')
    // Resolution must go through the same fingerprint filter, so it sees one grant.
    expect(store.resolveComponents(profile, fingerprint, 'personal').get('token')).toBe(SECRET)
  })

  test('resolving against a fingerprint no grant was activated for refuses', () => {
    const store = grantsWith([grant(fingerprint, 'CURRENT')], { token: SECRET })
    expect(() =>
      store.resolveComponents(profile, `v1:sha256:${'b'.repeat(64)}`, 'personal'),
    ).toThrow('no grant activated against')
  })

  test('two grants sharing a fingerprint and an account fail at load', () => {
    const result = GrantsFile.safeParse({
      version: 1,
      grants: [grant(fingerprint, 'ONE'), grant(fingerprint, 'TWO')],
    })
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(JSON.stringify(result.error.issues)).toContain('bound twice')
    }
  })

  test('a stale grant beside a rebinding still loads, because the fingerprint separates them', () => {
    const result = GrantsFile.safeParse({
      version: 1,
      grants: [grant(`v1:sha256:${'a'.repeat(64)}`, 'STALE'), grant(fingerprint, 'CURRENT')],
    })
    expect(result.success).toBe(true)
  })
})

describe('the committed snapshot is the HEAD tree, not the index', () => {
  let repo: TempRepo

  beforeEach(() => {
    repo = TempRepo.create()
    repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
    repo.writeYaml('catalog/meta/example.yaml', {
      id: 'example',
      name: 'Example',
      profiles: ['pat'],
    })
    repo.writeYaml(profilePath('example', 'pat'), {
      profile_id: 'pat',
      api_id: 'example',
      origins: ['https://api.example.com'],
      auth: { type: 'none' },
    })
    repo.commit('seed')
  })

  afterEach(() => repo.dispose())

  test('`git rm --cached` leaves the profile committed and still listed', () => {
    // The path leaves the index but stays in HEAD, and authority follows HEAD.
    repo.git('rm', '--cached', '--quiet', profilePath('example', 'pat'))
    const root = openRoot(repo.root)
    expect(root.git.trackedPaths().has(profilePath('example', 'pat'))).toBe(false)
    expect(root.git.committedPaths().has(profilePath('example', 'pat'))).toBe(true)
    expect(loadCommitted(root.git).profiles.has('example/pat')).toBe(true)
    expect(committedProfilesFor(root, 'example')).toEqual(['pat'])
  })

  test('`git rm` removes it from both, so it reports deleted', () => {
    repo.git('rm', '--quiet', profilePath('example', 'pat'))
    const root = openRoot(repo.root)
    // Still in HEAD until the removal is committed, so the worktree is dirty.
    expect(root.git.committedPaths().has(profilePath('example', 'pat'))).toBe(true)
    expect(root.git.pathState(profilePath('example', 'pat'))).toBe('tracked_deleted')
    const eligibility = evaluateEligibility(root, 'example', 'pat')
    expect(eligibility.eligible).toBe(false)
    if (!eligibility.eligible) expect(eligibility.code).toBe('deleted')
  })

  test('a committed removal drops the path from the snapshot', () => {
    repo.git('rm', '--quiet', profilePath('example', 'pat'))
    repo.commit('remove the profile')
    const root = openRoot(repo.root)
    expect(root.git.committedPaths().has(profilePath('example', 'pat'))).toBe(false)
    expect(committedProfilesFor(root, 'example')).toEqual([])
  })
})

describe('apply and migrate validate before they write', () => {
  let repo: TempRepo

  beforeEach(() => {
    repo = starterCatalogRepo()
    repo.commit('starter catalog')
  })

  afterEach(() => repo.dispose())

  test('a migration whose result would not validate leaves the worktree clean', () => {
    repo.write(
      'catalog/manifest.yaml',
      readFileSync(repo.path('catalog/manifest.yaml'), 'utf8').replace(
        'schema_version: 1',
        'schema_version: 0',
      ),
    )
    // A record linking a profile that does not exist fails a catalog-level check.
    repo.writeYaml('catalog/meta/orphan.yaml', {
      id: 'orphan',
      name: 'Orphan',
      profiles: ['absent'],
    })
    const head = repo.git('rev-parse', 'HEAD').trim()
    const before = repo.git('status', '--porcelain')
    expect(() => migrateCatalog(openRoot(repo.root))).toThrow('does not validate')
    // The test name used to be true only of the per-document checks.
    expect(repo.git('status', '--porcelain')).toBe(before)
    expect(repo.git('rev-parse', 'HEAD').trim()).toBe(head)
    expect(readFileSync(repo.path('catalog/manifest.yaml'), 'utf8')).toContain('schema_version: 0')
  })
})

describe('add refuses an identity the catalog already holds', () => {
  let repo: TempRepo

  beforeEach(() => {
    repo = starterCatalogRepo()
    repo.commit('starter catalog')
  })

  afterEach(() => repo.dispose())

  test('a canonical id that exists is refused, leaving the curated record intact', async () => {
    const before = readFileSync(repo.path(metadataPath('openalex')), 'utf8')
    await expect(
      runAdd(
        openRoot(repo.root),
        { positional: ['Clobbered'], flags: { manual: true, id: 'openalex' } },
        io,
        true,
      ),
    ).rejects.toThrow('already exists')
    expect(readFileSync(repo.path(metadataPath('openalex')), 'utf8')).toBe(before)
  })

  test('an id that resolves through an alias is refused', async () => {
    await expect(
      runAdd(
        openRoot(repo.root),
        { positional: ['Aliased'], flags: { manual: true, id: 'open-alex' } },
        io,
        true,
      ),
    ).rejects.toThrow('already resolves to')
  })

  test('--force overwrites deliberately', async () => {
    const result = (await runAdd(
      openRoot(repo.root),
      { positional: ['Replaced'], flags: { manual: true, id: 'openalex', force: true } },
      io,
      true,
    )) as { ok: boolean }
    expect(result.ok).toBe(true)
    expect(readFileSync(repo.path(metadataPath('openalex')), 'utf8')).toContain('Replaced')
  })

  test('a fresh id is written', async () => {
    const result = (await runAdd(
      openRoot(repo.root),
      { positional: ['Brand New API'], flags: { manual: true } },
      io,
      true,
    )) as { ok: boolean; api_id: string }
    expect(result.ok).toBe(true)
    expect(existsSync(repo.path(metadataPath('brand-new-api')))).toBe(true)
  })
})

describe('a merge chain resolves to its terminal target on every surface', () => {
  let repo: TempRepo
  let storePath: string

  beforeEach(() => {
    repo = TempRepo.create()
    repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
    // A -> B -> C, where B was merged into C after A was already pointing at B.
    repo.writeYaml('catalog/meta/c.yaml', { id: 'c', name: 'Target C' })
    repo.writeYaml('catalog/meta/b.yaml', {
      id: 'b',
      name: 'Middle B',
      lifecycle: 'merged',
      merged_into: 'c',
    })
    repo.writeYaml('catalog/meta/a.yaml', {
      id: 'a',
      name: 'Origin A',
      lifecycle: 'merged',
      merged_into: 'b',
    })
    repo.commit('a merge chain')
    storePath = join(scratch, 'catalog.db')
  })

  afterEach(() => repo.dispose())

  test('search resolves the whole chain, not one hop', () => {
    buildStore(openRoot(repo.root), { storePath })
    const opened = openStore(openRoot(repo.root), { storePath })
    try {
      const catalog = new CatalogQuery(opened.db)
      expect(catalog.resolve('a')?.id).toBe('c')
      expect(catalog.resolve('b')?.id).toBe('c')
      const first = catalog.search('a').results[0]
      expect(first?.id).toBe('c')
      expect(first?.redirected_from).toBe('a')
    } finally {
      opened.close()
    }
  })

  test('a merged record is never its own search hit', () => {
    buildStore(openRoot(repo.root), { storePath })
    const opened = openStore(openRoot(repo.root), { storePath })
    try {
      const ids = new CatalogQuery(opened.db).search('', { limit: 50 }).results.map((r) => r.id)
      expect(ids).toEqual(['c'])
    } finally {
      opened.close()
    }
  })
})

describe('draft means an uncommitted worktree change and nothing else', () => {
  test('a catalog outside a repository is not a tree of drafts', () => {
    const plain = join(scratch, 'plain')
    mkdirSync(join(plain, 'catalog', 'meta'), { recursive: true })
    writeFileSync(join(plain, 'catalog', 'manifest.yaml'), stringify(fixtureManifest()))
    writeFileSync(
      join(plain, 'catalog', 'meta', 'example.yaml'),
      stringify({ id: 'example', name: 'Example' }),
    )
    const root = openRoot(plain)
    expect(root.git.available).toBe(false)
    const entry = loadWorkingTree(root.path, root.git).records.get('example')
    expect(entry?.state).toBe('no_snapshot')
    expect(entry?.draft).toBe(false)
  })

  test('a filtered path is reported filtered, not draft', () => {
    const repo = TempRepo.create()
    try {
      repo.write('.gitattributes', 'catalog/** text eol=lf\n')
      repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
      repo.writeYaml('catalog/meta/example.yaml', { id: 'example', name: 'Example' })
      repo.commit('filtered catalog')
      const root = openRoot(repo.root)
      const entry = loadWorkingTree(root.path, root.git).records.get('example')
      expect(entry?.state).toBe('filtered')
      expect(entry?.draft).toBe(false)
    } finally {
      repo.dispose()
    }
  })

  test('an untracked and a modified record are both drafts', () => {
    const repo = TempRepo.create()
    try {
      repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
      repo.writeYaml('catalog/meta/committed.yaml', { id: 'committed', name: 'Committed' })
      repo.commit('seed')
      repo.writeYaml('catalog/meta/committed.yaml', {
        id: 'committed',
        name: 'Committed',
        description: 'edited',
      })
      repo.writeYaml('catalog/meta/fresh.yaml', { id: 'fresh', name: 'Fresh' })
      const root = openRoot(repo.root)
      const snapshot = loadWorkingTree(root.path, root.git)
      expect(snapshot.records.get('committed')?.draft).toBe(true)
      expect(snapshot.records.get('fresh')?.draft).toBe(true)
    } finally {
      repo.dispose()
    }
  })
})

describe('a broken catalog root config is not "not configured"', () => {
  test('unparseable YAML reports config_unreadable naming the file', () => {
    const configHome = join(scratch, 'config')
    mkdirSync(join(configHome, 'apimanac'), { recursive: true })
    writeFileSync(join(configHome, 'apimanac', 'config.yaml'), 'catalog_root: [unclosed\n')
    process.env.XDG_CONFIG_HOME = configHome
    delete process.env.APIMANAC_CATALOG
    resetXdgForTests()
    const resolution = resolveCatalogRoot()
    expect(resolution.ok).toBe(false)
    if (!resolution.ok) {
      expect(resolution.code).toBe('config_unreadable')
      expect(resolution.message).toContain('config.yaml')
    }
  })

  test('a non-string catalog_root reports config_unreadable', () => {
    const configHome = join(scratch, 'config2')
    mkdirSync(join(configHome, 'apimanac'), { recursive: true })
    writeFileSync(join(configHome, 'apimanac', 'config.yaml'), 'catalog_root: 42\n')
    process.env.XDG_CONFIG_HOME = configHome
    delete process.env.APIMANAC_CATALOG
    resetXdgForTests()
    const resolution = resolveCatalogRoot()
    expect(resolution.ok).toBe(false)
    if (!resolution.ok) expect(resolution.code).toBe('config_unreadable')
  })

  test('an absent config file is still not_configured', () => {
    process.env.XDG_CONFIG_HOME = join(scratch, 'empty')
    delete process.env.APIMANAC_CATALOG
    resetXdgForTests()
    const resolution = resolveCatalogRoot()
    expect(resolution.ok).toBe(false)
    if (!resolution.ok) expect(resolution.code).toBe('not_configured')
  })
})

describe('an explicit --catalog outranks the environment', () => {
  test('the argument wins and the environment value is not consulted', () => {
    const repo = starterCatalogRepo()
    const other = starterCatalogRepo()
    try {
      repo.commit('one')
      other.commit('two')
      process.env.APIMANAC_CATALOG = other.root
      resetXdgForTests()
      const resolution = resolveCatalogRoot(repo.root)
      expect(resolution.ok).toBe(true)
      if (resolution.ok) {
        expect(resolution.source).toBe('argument')
        expect(resolution.path).toBe(repo.root)
      }
    } finally {
      repo.dispose()
      other.dispose()
      delete process.env.APIMANAC_CATALOG
    }
  })
})

describe('a verified profile is what evidence pins', () => {
  test('a contract-hash-changing edit refuses even when the file is committed', () => {
    const repo = starterCatalogRepo()
    try {
      const file = profilePath('openalex', 'public')
      const document = parse(readFileSync(repo.path(file), 'utf8')) as Record<string, unknown>
      const candidate = ExecutionProfile.parse(document)
      document.verification = {
        state: 'verified',
        verified_at: '2026-01-01T00:00:00Z',
        evidence: {
          contract_hash: contractHash(candidate),
          method: 'GET',
          path: '/works',
          status: 200,
          response_hash: `v1:sha256:${'0'.repeat(64)}`,
          timestamp: '2026-01-01T00:00:00Z',
          tool_version: '0.0.0',
        },
      }
      repo.writeYaml(file, document)
      repo.commit('verify openalex/public')
      expect(evaluateEligibility(openRoot(repo.root), 'openalex', 'public').eligible).toBe(true)

      // Widen the permissions and commit: the evidence hash no longer matches.
      document.permissions = [{ method: 'GET', path: '/**', decision: 'auto' }]
      repo.writeYaml(file, document)
      repo.commit('widen the permissions without re-verifying')
      const after = evaluateEligibility(openRoot(repo.root), 'openalex', 'public')
      expect(after.eligible).toBe(false)
      if (!after.eligible) expect(after.code).toBe('evidence_mismatch')
    } finally {
      repo.dispose()
    }
  })
})
