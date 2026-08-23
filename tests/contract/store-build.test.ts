import { Database } from 'bun:sqlite'
import { existsSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { buildStore, canonicalInputHash } from '../../src/store/build'
import { isStale, openStore } from '../../src/store/open'
import { openRoot, starterCatalogRepo } from '../helpers/catalog'
import type { TempRepo } from '../helpers/repo'

describe('the derived store build', () => {
  let repo: TempRepo
  let cacheDir: string
  let storePath: string

  beforeEach(() => {
    repo = starterCatalogRepo()
    repo.commit('seed catalog')
    cacheDir = mkdtempSync(join(tmpdir(), 'apimanac-store-'))
    storePath = join(cacheDir, 'catalog.db')
  })

  afterEach(() => {
    repo.dispose()
    rmSync(cacheDir, { recursive: true, force: true })
  })

  test('applies to a fresh database and populates both projections', () => {
    const root = openRoot(repo.root)
    const result = buildStore(root, { storePath })
    expect(result.discoveryRecords).toBe(5)
    expect(result.authorityRecords).toBe(5)
    expect(result.indexRows).toBe(5)

    const db = new Database(storePath, { readonly: true })
    try {
      const tables = db
        .query<{ name: string }, []>("SELECT name FROM sqlite_master WHERE type = 'table'")
        .all()
        .map((row) => row.name)
      for (const expected of ['meta', 'd_api', 'a_api', 'd_profile', 'a_profile', 'fts_api']) {
        expect(tables).toContain(expected)
      }
    } finally {
      db.close()
    }
  })

  test('rebuilding several times keeps identical row counts and no duplicate hits', () => {
    const root = openRoot(repo.root)
    const counts: number[] = []
    for (let i = 0; i < 3; i++) {
      counts.push(buildStore(root, { storePath }).indexRows)
    }
    expect(new Set(counts).size).toBe(1)

    const db = new Database(storePath, { readonly: true })
    try {
      const hits = db
        .query<{ api_id: string }, [string]>('SELECT api_id FROM fts_api WHERE fts_api MATCH ?')
        .all('openalex')
      expect(hits.length).toBe(new Set(hits.map((h) => h.api_id)).size)
    } finally {
      db.close()
    }
  })

  test('a deleted record leaves no surviving index row', () => {
    const root = openRoot(repo.root)
    buildStore(root, { storePath })
    repo.remove('catalog/meta/datacite.yaml')
    repo.remove('catalog/execution/datacite/public.yaml')
    const after = buildStore(openRoot(repo.root), { storePath })
    expect(after.indexRows).toBe(4)

    const db = new Database(storePath, { readonly: true })
    try {
      expect(
        db
          .query<{ n: number }, [string]>('SELECT COUNT(*) AS n FROM d_api WHERE id = ?')
          .get('datacite')?.n,
      ).toBe(0)
      expect(
        db
          .query<{ api_id: string }, [string]>('SELECT api_id FROM fts_api WHERE fts_api MATCH ?')
          .all('datacite').length,
      ).toBe(0)
    } finally {
      db.close()
    }
  })

  test('an index hit joins back to its record', () => {
    const root = openRoot(repo.root)
    buildStore(root, { storePath })
    const db = new Database(storePath, { readonly: true })
    try {
      const row = db
        .query<{ api_id: string; name: string }, [string]>(
          'SELECT f.api_id AS api_id, a.name AS name FROM fts_api f JOIN d_api a ON a.id = f.api_id WHERE fts_api MATCH ?',
        )
        .get('openalex')
      expect(row?.api_id).toBe('openalex')
      expect(row?.name).toBe('OpenAlex')
    } finally {
      db.close()
    }
  })

  test('a draft-only profile is in discovery and absent from authority', () => {
    repo.writeYaml('catalog/meta/draftonly.yaml', {
      id: 'draftonly',
      name: 'Draft Only',
      profiles: ['public'],
    })
    repo.writeYaml('catalog/execution/draftonly/public.yaml', {
      profile_id: 'public',
      api_id: 'draftonly',
      origins: ['https://api.draftonly.example'],
      auth: { type: 'none' },
    })
    const root = openRoot(repo.root)
    buildStore(root, { storePath })
    const db = new Database(storePath, { readonly: true })
    try {
      const discovery = db
        .query<{ draft: number }, [string]>('SELECT draft FROM d_profile WHERE api_id = ?')
        .get('draftonly')
      expect(discovery?.draft).toBe(1)
      expect(
        db
          .query<{ n: number }, [string]>('SELECT COUNT(*) AS n FROM a_profile WHERE api_id = ?')
          .get('draftonly')?.n,
      ).toBe(0)
    } finally {
      db.close()
    }
  })

  test('a committed profile deleted in the worktree stays in the authority projection', () => {
    const root = openRoot(repo.root)
    buildStore(root, { storePath })
    repo.remove('catalog/execution/openalex/public.yaml')
    buildStore(openRoot(repo.root), { storePath, skipValidation: true })
    const db = new Database(storePath, { readonly: true })
    try {
      expect(
        db
          .query<{ n: number }, [string]>('SELECT COUNT(*) AS n FROM d_profile WHERE api_id = ?')
          .get('openalex')?.n,
      ).toBe(0)
      expect(
        db
          .query<{ n: number }, [string]>('SELECT COUNT(*) AS n FROM a_profile WHERE api_id = ?')
          .get('openalex')?.n,
      ).toBe(1)
    } finally {
      db.close()
    }
  })

  test('a build refusing on validation failure leaves the previous store in place', () => {
    const root = openRoot(repo.root)
    buildStore(root, { storePath })
    const before = Bun.file(storePath).size
    repo.writeYaml('catalog/meta/broken.yaml', { id: 'Broken_Id', name: 'Broken' })
    expect(() => buildStore(openRoot(repo.root), { storePath })).toThrow('does not validate')
    expect(existsSync(storePath)).toBe(true)
    expect(Bun.file(storePath).size).toBe(before)
    expect(existsSync(`${storePath}.tmp-${process.pid}`)).toBe(false)
  })

  test('an interrupted build leaves the previous store queryable and no partial store', () => {
    const root = openRoot(repo.root)
    buildStore(root, { storePath })
    // Simulate the interruption by leaving a stale temp file behind.
    const temporary = `${storePath}.tmp-${process.pid}`
    writeFileSync(temporary, 'partial')
    const db = new Database(storePath, { readonly: true })
    try {
      expect(db.query<{ n: number }, []>('SELECT COUNT(*) AS n FROM d_api').get()?.n).toBe(5)
    } finally {
      db.close()
    }
    // The next build overwrites the stale temp rather than adopting it.
    buildStore(openRoot(repo.root), { storePath })
    expect(existsSync(temporary)).toBe(false)
  })
})

describe('staleness and automatic rebuild', () => {
  let repo: TempRepo
  let cacheDir: string
  let storePath: string

  beforeEach(() => {
    repo = starterCatalogRepo()
    repo.commit('seed catalog')
    cacheDir = mkdtempSync(join(tmpdir(), 'apimanac-store-'))
    storePath = join(cacheDir, 'catalog.db')
  })

  afterEach(() => {
    repo.dispose()
    rmSync(cacheDir, { recursive: true, force: true })
  })

  test('a missing store is stale and is built on first read', () => {
    const root = openRoot(repo.root)
    expect(isStale(root, storePath)).toBe(true)
    const opened = openStore(root, { storePath })
    try {
      expect(opened.rebuilt).toBe(true)
      expect(opened.db.query<{ n: number }, []>('SELECT COUNT(*) AS n FROM d_api').get()?.n).toBe(5)
    } finally {
      opened.close()
    }
  })

  test('an unchanged catalog is not stale', () => {
    const root = openRoot(repo.root)
    buildStore(root, { storePath })
    expect(isStale(openRoot(repo.root), storePath)).toBe(false)
  })

  test('a worktree edit makes the store stale', () => {
    buildStore(openRoot(repo.root), { storePath })
    repo.write('catalog/meta/openalex.yaml', `${Bun.file(repo.path('catalog/meta/openalex.yaml'))}`)
    repo.writeYaml('catalog/meta/extra.yaml', { id: 'extra', name: 'Extra' })
    expect(isStale(openRoot(repo.root), storePath)).toBe(true)
  })

  test('a commit that leaves the worktree byte-identical still makes the store stale', () => {
    repo.writeYaml('catalog/meta/pending.yaml', { id: 'pending', name: 'Pending' })
    buildStore(openRoot(repo.root), { storePath })
    const beforeHash = canonicalInputHash(openRoot(repo.root))
    repo.commit('commit the pending record')
    const afterHash = canonicalInputHash(openRoot(repo.root))
    expect(afterHash).not.toBe(beforeHash)
    expect(isStale(openRoot(repo.root), storePath)).toBe(true)
  })

  test('checking out a different commit makes the store stale', () => {
    const first = repo.commit('first')
    repo.writeYaml('catalog/meta/second.yaml', { id: 'second', name: 'Second' })
    repo.commit('second')
    buildStore(openRoot(repo.root), { storePath })
    expect(isStale(openRoot(repo.root), storePath)).toBe(false)
    repo.git('checkout', '--quiet', first)
    expect(isStale(openRoot(repo.root), storePath)).toBe(true)
  })

  test('a rebuild triggered from an unrelated directory writes only under the store path', () => {
    const unrelated = mkdtempSync(join(tmpdir(), 'apimanac-elsewhere-'))
    const previous = process.cwd()
    process.chdir(unrelated)
    try {
      const opened = openStore(openRoot(repo.root), { storePath })
      opened.close()
      expect(existsSync(storePath)).toBe(true)
      expect([...new Bun.Glob('**/*').scanSync({ cwd: unrelated, onlyFiles: true })]).toEqual([])
    } finally {
      process.chdir(previous)
      rmSync(unrelated, { recursive: true, force: true })
    }
  })
})
