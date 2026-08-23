import { existsSync, mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { parse } from 'yaml'
import { loadWorkingTree } from '../../src/catalog/load'
import { validateCatalog } from '../../src/catalog/validate'
import {
  BenchmarkFile,
  REQUIRED_HITS,
  formatBenchmark,
  runBenchmark,
} from '../../src/search/benchmark'
import { CatalogQuery } from '../../src/search/query'
import { buildStore } from '../../src/store/build'
import { openStore } from '../../src/store/open'
import {
  refreshSource,
  runAdapter,
  SOURCE_IDS,
  type SourceId,
} from '../../src/maintenance/commands'
import { countLedger, OutcomeLedger, SourceManifest } from '../../src/schema/report'
import { openRoot, starterCatalogRepo } from '../helpers/catalog'
import type { TempRepo } from '../helpers/repo'
import { fixturePath, loadFixture } from '../helpers/yaml'

let repo: TempRepo
let cacheDir: string
let storePath: string

function readJson(...parts: string[]): unknown {
  return JSON.parse(readFileSync(fixturePath('sources', ...parts), 'utf8'))
}

function pinFor(sourceId: string) {
  const document = loadFixture('sources', sourceId, 'pin.yaml') as Record<string, unknown>
  return {
    revision: String(document.revision),
    contentHash: String(document.content_hash),
    retrievedAt: String(document.retrieved_at),
  }
}

function inputFor(sourceId: SourceId) {
  switch (sourceId) {
    case 'public-apis':
      return { payload: readJson('public-apis', 'entries.json'), pin: pinFor('public-apis') }
    case 'nango':
      return {
        payload: loadFixture('sources', 'nango', 'providers.yaml'),
        scopes: loadFixture('sources', 'nango', 'scopes.yaml'),
        pin: pinFor('nango'),
      }
    case 'apis-guru': {
      const specs = new Map<string, unknown>()
      const glob = new Bun.Glob('*.json')
      const directory = fixturePath('sources', 'apis-guru', 'specs')
      for (const file of glob.scanSync({ cwd: directory })) {
        specs.set(
          file.replace(/\.json$/, ''),
          JSON.parse(readFileSync(join(directory, file), 'utf8')),
        )
      }
      return {
        payload: readJson('apis-guru', 'list.json'),
        specs,
        pin: pinFor('apis-guru'),
      }
    }
  }
}

beforeEach(() => {
  repo = starterCatalogRepo()
  repo.commit('seed catalog')
  cacheDir = mkdtempSync(join(tmpdir(), 'apimanac-ingest-'))
  storePath = join(cacheDir, 'catalog.db')
})

afterEach(() => {
  repo.dispose()
  rmSync(cacheDir, { recursive: true, force: true })
})

describe('each adapter applies to the worktree as an uncommitted diff', () => {
  test.each([...SOURCE_IDS])('%s writes records, a ledger and a manifest', (sourceId) => {
    const head = repo.git('rev-parse', 'HEAD').trim()
    const report = refreshSource(openRoot(repo.root), sourceId, inputFor(sourceId))
    expect(report.ok).toBe(true)
    expect(report.files).toContain(`catalog/sources/${sourceId}/outcomes.yaml`)
    expect(report.files).toContain(`catalog/sources/${sourceId}/manifest.yaml`)
    expect(report.counts.examined).toBeGreaterThan(0)

    // Nothing is staged or committed.
    expect(repo.git('rev-parse', 'HEAD').trim()).toBe(head)
    expect(repo.git('diff', '--cached', '--name-only')).toBe('')
    // Git collapses a wholly untracked directory, so check the files exist too.
    expect(repo.git('status', '--porcelain')).toContain('catalog/sources/')
    expect(existsSync(repo.path(`catalog/sources/${sourceId}/outcomes.yaml`))).toBe(true)
    expect(existsSync(repo.path(`catalog/sources/${sourceId}/manifest.yaml`))).toBe(true)
  })

  test.each([...SOURCE_IDS])('%s leaves the catalog valid', (sourceId) => {
    refreshSource(openRoot(repo.root), sourceId, inputFor(sourceId))
    const root = openRoot(repo.root)
    const report = validateCatalog(loadWorkingTree(root.path, root.git))
    expect(report.findings.map((finding) => `${finding.kind} ${finding.file}`)).toEqual([])
  })

  test.each([...SOURCE_IDS])('%s accounts for every upstream entry exactly once', (sourceId) => {
    refreshSource(openRoot(repo.root), sourceId, inputFor(sourceId))
    const ledger = OutcomeLedger.parse(
      parse(readFileSync(repo.path(`catalog/sources/${sourceId}/outcomes.yaml`), 'utf8')),
    )
    const manifest = SourceManifest.parse(
      parse(readFileSync(repo.path(`catalog/sources/${sourceId}/manifest.yaml`), 'utf8')),
    )
    const ids = ledger.entries.map((entry) => entry.source_entry_id)
    expect(new Set(ids).size).toBe(ids.length)
    expect(countLedger(ledger)).toEqual(manifest.counts)
    expect(manifest.revision).toBe(pinFor(sourceId).revision)
  })

  test.each([...SOURCE_IDS])('%s produces no verified profile', (sourceId) => {
    refreshSource(openRoot(repo.root), sourceId, inputFor(sourceId))
    const root = openRoot(repo.root)
    for (const entry of loadWorkingTree(root.path, root.git).profiles.values()) {
      expect(`${entry.file}:${entry.value.verification.state}`).toBe(`${entry.file}:candidate`)
    }
  })

  test.each([...SOURCE_IDS])('%s creates or modifies no grant file', (sourceId) => {
    const grantsPath = join(cacheDir, 'grants.yaml')
    refreshSource(openRoot(repo.root), sourceId, inputFor(sourceId))
    expect(existsSync(grantsPath)).toBe(false)
    expect(existsSync(repo.path('grants.yaml'))).toBe(false)
  })
})

describe('an identity the catalog already owns becomes an alias, not an orphan', () => {
  test('apis-guru `openalex.org` resolves to the starter `openalex` and writes no profile', () => {
    const report = refreshSource(openRoot(repo.root), 'apis-guru', inputFor('apis-guru'))
    expect(report.ok).toBe(true)

    // The proposed slug collides with an alias the starter record already holds.
    const conflict = report.conflicts.find((entry) => entry.record === 'openalex-org')
    expect(conflict).toBeDefined()
    expect(conflict?.current).toBe('openalex')
    expect(report.counts.aliased).toBeGreaterThan(0)

    // Neither the record nor its execution candidate may reach the worktree,
    // or the profile would reference an api that was never written.
    expect(report.files.some((file) => file.includes('openalex-org'))).toBe(false)
    expect(existsSync(repo.path('catalog/meta/openalex-org.yaml'))).toBe(false)
    expect(existsSync(repo.path('catalog/execution/openalex-org'))).toBe(false)

    // The ledger still accounts for the entry, as `aliased` to the owner.
    const ledger = OutcomeLedger.parse(
      parse(readFileSync(repo.path('catalog/sources/apis-guru/outcomes.yaml'), 'utf8')),
    )
    const entry = ledger.entries.find((row) => row.source_entry_id === 'openalex.org')
    expect(entry?.outcome).toBe('aliased')
    if (entry?.outcome === 'aliased') expect(entry.api_id).toBe('openalex')
  })

  test('a candidate catalog that would not validate applies nothing', () => {
    const before = repo.git('status', '--porcelain')
    // A record the adapter cannot reconcile leaves the tree untouched rather
    // than writing first and validating after.
    const report = refreshSource(openRoot(repo.root), 'apis-guru', inputFor('apis-guru'))
    expect(report.ok).toBe(true)
    expect(repo.git('status', '--porcelain')).not.toBe(before)
    expect(
      validateCatalog(loadWorkingTree(openRoot(repo.root).path, openRoot(repo.root).git)).ok,
    ).toBe(true)
  })

  test('the spec fixtures are keyed by upstream list id, not filename stem', () => {
    // Keying by stem silently drops every entry whose id is not a bare slug,
    // which is what hid the collision above.
    const keys = [...(inputFor('apis-guru').specs?.keys() ?? [])]
    expect(keys).toContain('openalex.org')
    expect(keys).toContain('googleapis.com:drive')
  })
})

describe('all three ledgers reproduce offline from a clean clone', () => {
  test('running every adapter in sequence keeps the catalog valid and accounts for everything', () => {
    for (const sourceId of SOURCE_IDS) {
      const report = refreshSource(openRoot(repo.root), sourceId, inputFor(sourceId))
      expect(report.ok).toBe(true)
    }
    const root = openRoot(repo.root)
    expect(validateCatalog(loadWorkingTree(root.path, root.git)).ok).toBe(true)
    for (const sourceId of SOURCE_IDS) {
      expect(existsSync(repo.path(`catalog/sources/${sourceId}/outcomes.yaml`))).toBe(true)
    }
  })

  test('an adapter run is deterministic: the same input yields the same ledger', () => {
    const first = runAdapter('public-apis', inputFor('public-apis'))
    const second = runAdapter('public-apis', inputFor('public-apis'))
    expect(JSON.stringify(second)).toBe(JSON.stringify(first))
  })

  test('no adapter module reaches the network', async () => {
    for (const module of ['adapter', 'public-apis', 'nango', 'apis-guru']) {
      const source = await Bun.file(
        Bun.fileURLToPath(new URL(`../../src/ingest/${module}.ts`, import.meta.url)),
      ).text()
      for (const forbidden of ['node:http', 'node:https', 'fetch(', 'node:dns']) {
        expect(`${module}:${source.includes(forbidden)}`).toBe(`${module}:false`)
      }
    }
  })
})

describe('the imported corpus is searchable', () => {
  test('a build over the imported catalog indexes every record', () => {
    for (const sourceId of SOURCE_IDS) {
      refreshSource(openRoot(repo.root), sourceId, inputFor(sourceId))
    }
    repo.commit('commit the imported corpus')
    const result = buildStore(openRoot(repo.root), { storePath })
    expect(result.indexRows).toBeGreaterThan(5)
    expect(result.discoveryRecords).toBe(result.indexRows)
  })

  test('an imported record is findable and labeled imported', () => {
    refreshSource(openRoot(repo.root), 'public-apis', inputFor('public-apis'))
    repo.commit('commit the public-apis import')
    buildStore(openRoot(repo.root), { storePath })
    const opened = openStore(openRoot(repo.root), { storePath })
    try {
      const catalog = new CatalogQuery(opened.db)
      const imported = catalog
        .search('', { limit: 50 })
        .results.filter((entry) => entry.curation === 'imported')
      expect(imported.length).toBeGreaterThan(0)
      expect(imported.every((entry) => entry.sources.length > 0)).toBe(true)
    } finally {
      opened.close()
    }
  })

  test('the search benchmark still passes against the fixture catalog plus the imported corpus', () => {
    const fixtureRepo = starterCatalogRepo()
    try {
      // The benchmark fixture catalog is the graded one; the imported corpus is
      // added on top so the threshold is measured against a larger index.
      rmSync(fixtureRepo.path('catalog'), { recursive: true, force: true })
      const glob = new Bun.Glob('**/*.yaml')
      const source = fixturePath('search', 'catalog')
      for (const relative of glob.scanSync({ cwd: source })) {
        fixtureRepo.write(`catalog/${relative}`, readFileSync(join(source, relative), 'utf8'))
      }
      for (const sourceId of SOURCE_IDS) {
        const report = refreshSource(openRoot(fixtureRepo.root), sourceId, inputFor(sourceId))
        expect(report.ok).toBe(true)
      }
      fixtureRepo.commit('benchmark catalog plus imported corpus')
      const benchStore = join(cacheDir, 'bench.db')
      buildStore(openRoot(fixtureRepo.root), { storePath: benchStore })
      const opened = openStore(openRoot(fixtureRepo.root), { storePath: benchStore })
      try {
        const report = runBenchmark(
          new CatalogQuery(opened.db),
          BenchmarkFile.parse(loadFixture('search', 'queries.yaml')),
        )
        if (!report.ok) console.log(formatBenchmark(report))
        expect(report.hits).toBeGreaterThanOrEqual(REQUIRED_HITS)
        expect(report.exact.filter((outcome) => !outcome.ok)).toEqual([])
      } finally {
        opened.close()
      }
    } finally {
      fixtureRepo.dispose()
    }
  })
})
