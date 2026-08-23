import { existsSync, readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { parse, stringify } from 'yaml'
import { loadWorkingTree, metadataPath, profilePath } from '../../src/catalog/load'
import { validateCatalog } from '../../src/catalog/validate'
import {
  extractLocal,
  extractOpenApi,
  slugify,
  templateToPattern,
} from '../../src/maintenance/extract'
import {
  migrateCatalog,
  refreshFromCandidate,
  runAdd,
  type RefreshCandidate,
} from '../../src/maintenance/commands'
import { configureExternalExtractor } from '../../src/maintenance/fetch'
import { MAINTENANCE_POLICY } from '../../src/policy/maintenance'
import { openRoot, starterCatalogRepo } from '../helpers/catalog'
import type { TempRepo } from '../helpers/repo'

let repo: TempRepo

const io = { out: () => undefined, err: () => undefined }

beforeEach(() => {
  repo = starterCatalogRepo()
  repo.commit('seed catalog')
  configureExternalExtractor(undefined)
})

afterEach(() => {
  repo.dispose()
  configureExternalExtractor(undefined)
})

function argv(positional: string[], flags: Record<string, string | boolean> = {}) {
  return { positional, flags }
}

describe('the fixed maintenance policy', () => {
  test('is HTTPS only, global only, and carries no credential', () => {
    expect(MAINTENANCE_POLICY.allowPlainHttp).toBe(false)
    expect(MAINTENANCE_POLICY.allowNonGlobalAddresses).toBe(false)
    expect(MAINTENANCE_POLICY.credentialsPermitted).toBe(false)
    expect(MAINTENANCE_POLICY.maxRedirects).toBeGreaterThan(0)
    expect(MAINTENANCE_POLICY.maxResponseBytes).toBeGreaterThan(0)
    expect(MAINTENANCE_POLICY.timeoutMs).toBeGreaterThan(0)
  })

  test('is a constant, not derived from any profile in the catalog', () => {
    // The seed catalog contains profiles; none of them appears in the policy.
    expect(Object.keys(MAINTENANCE_POLICY)).not.toContain('allowedOrigins')
    expect(MAINTENANCE_POLICY.label).toBe('maintenance')
  })
})

describe('add refuses a non-public URL under the fixed policy', () => {
  test('a plain http URL is refused and contacts no external extractor', async () => {
    let contacted = false
    configureExternalExtractor({
      name: 'test',
      extract: async () => {
        contacted = true
        return { name: 'Should not happen' }
      },
    })
    const result = (await runAdd(
      openRoot(repo.root),
      argv(['http://example.com/openapi.json']),
      io,
      true,
    )) as { ok: boolean; message: string; files: string[] }
    expect(result.ok).toBe(false)
    expect(result.message).toContain('HTTPS only')
    expect(result.files).toEqual([])
    expect(contacted).toBe(false)
  })

  test('a URL resolving to a loopback address is refused', async () => {
    const result = (await runAdd(
      openRoot(repo.root),
      argv(['https://127.0.0.1/openapi.json']),
      io,
      true,
    )) as { ok: boolean; message: string }
    expect(result.ok).toBe(false)
    expect(result.message).toMatch(/loopback|refused/)
  })

  test('a private-scoped profile in the catalog does not widen the policy', async () => {
    repo.writeYaml('catalog/meta/localthing.yaml', {
      id: 'localthing',
      name: 'Local thing',
      profiles: ['local'],
    })
    repo.writeYaml('catalog/execution/localthing/local.yaml', {
      profile_id: 'local',
      api_id: 'localthing',
      origins: ['http://127.0.0.1:9999'],
      auth: { type: 'none' },
      network_scope: 'private',
    })
    repo.commit('add a private-scoped profile')
    const result = (await runAdd(
      openRoot(repo.root),
      argv(['https://10.0.0.1/openapi.json']),
      io,
      true,
    )) as { ok: boolean }
    expect(result.ok).toBe(false)
  })

  test('with no extractor configured, a failed local extraction writes nothing', async () => {
    const before = loadWorkingTree(repo.root, openRoot(repo.root).git).records.size
    const result = (await runAdd(
      openRoot(repo.root),
      argv(['http://example.com/doc']),
      io,
      true,
    )) as { ok: boolean; files: string[] }
    expect(result.files).toEqual([])
    expect(loadWorkingTree(repo.root, openRoot(repo.root).git).records.size).toBe(before)
  })
})

describe('add --manual', () => {
  test('creates a record with manual provenance, no URL, and no execution profile', async () => {
    const result = (await runAdd(
      openRoot(repo.root),
      argv(['Some New API'], { manual: true }),
      io,
      true,
    )) as { ok: boolean; api_id: string; extraction_method: string; files: string[] }
    expect(result.ok).toBe(true)
    expect(result.api_id).toBe('some-new-api')
    expect(result.extraction_method).toBe('manual')
    expect(result.files).toEqual([metadataPath('some-new-api')])

    const record = parse(readFileSync(repo.path(metadataPath('some-new-api')), 'utf8')) as {
      sources: string[]
      profiles: string[]
      provenance: Record<string, { source: string; curated: boolean }>
    }
    expect(record.sources).toEqual(['manual'])
    expect(record.profiles).toEqual([])
    expect(record.provenance.name?.source).toBe('manual')
    expect(record.provenance.name?.curated).toBe(true)
  })

  test('leaves the change uncommitted and stages nothing', async () => {
    const head = repo.git('rev-parse', 'HEAD').trim()
    const staged = repo.git('diff', '--cached', '--name-only')
    await runAdd(openRoot(repo.root), argv(['Another API'], { manual: true }), io, true)
    expect(repo.git('rev-parse', 'HEAD').trim()).toBe(head)
    expect(repo.git('diff', '--cached', '--name-only')).toBe(staged)
    expect(repo.git('status', '--porcelain')).toContain('another-api.yaml')
  })

  test('a name that does not slugify needs an explicit id', async () => {
    await expect(
      runAdd(openRoot(repo.root), argv(['!!!'], { manual: true }), io, true),
    ).rejects.toThrow('--id')
  })
})

describe('local and OpenAPI extraction', () => {
  test('an OpenAPI 3 document yields origins from its servers, not from the URL', () => {
    const document = {
      openapi: '3.0.3',
      info: { title: 'Widget API', description: 'Widgets, gadgets and gizmos.' },
      servers: [{ url: 'https://api.widget.example/v2' }],
      paths: { '/widgets': { get: {} }, '/widgets/{id}': { get: {}, post: {} } },
    }
    const extraction = extractOpenApi(
      Buffer.from(JSON.stringify(document)),
      'https://docs.widget.example/openapi.json',
    )
    expect(extraction?.method).toBe('openapi')
    expect(extraction?.origins).toEqual(['https://api.widget.example'])
    expect(extraction?.basePath).toBe('/v2')
    expect(extraction?.specFormat).toBe('openapi-3')
    expect(extraction?.operations.map((operation) => operation.path)).toEqual([
      '/widgets',
      '/widgets/*',
    ])
  })

  test('a Swagger 2 host, basePath and schemes triple converts correctly', () => {
    const document = {
      swagger: '2.0',
      info: { title: 'Legacy API' },
      host: 'api.legacy.example',
      basePath: '/v1',
      schemes: ['https', 'http'],
      paths: { '/things': { get: {} } },
    }
    const extraction = extractOpenApi(Buffer.from(JSON.stringify(document)), 'https://x.example/s')
    expect(extraction?.origins).toEqual(['https://api.legacy.example', 'http://api.legacy.example'])
    expect(extraction?.basePath).toBe('/v1')
    expect(extraction?.specFormat).toBe('swagger-2')
  })

  test('a server template yields no origin rather than an invented one', () => {
    const document = {
      openapi: '3.1.0',
      info: { title: 'Templated' },
      servers: [{ url: '{scheme}://{host}/v1' }],
    }
    expect(
      extractOpenApi(Buffer.from(JSON.stringify(document)), 'https://x.example')?.origins,
    ).toEqual([])
  })

  test('a document that is not a specification is not parsed as one', () => {
    expect(
      extractOpenApi(Buffer.from('<html><title>Docs</title></html>'), 'https://x.example'),
    ).toBeUndefined()
    expect(
      extractOpenApi(Buffer.from(JSON.stringify({ hello: 'world' })), 'https://x.example'),
    ).toBeUndefined()
  })

  test('local extraction reads a title and description and invents no origin', () => {
    const html = `<html><head><title>Widget Docs</title>
      <meta name="description" content="The Widget API reference." /></head></html>`
    const extraction = extractLocal(Buffer.from(html), 'https://docs.widget.example')
    expect(extraction?.method).toBe('local')
    expect(extraction?.name).toBe('Widget Docs')
    expect(extraction?.description).toBe('The Widget API reference.')
    expect(extraction?.origins).toEqual([])
  })

  test('a documentation page with no title yields nothing', () => {
    expect(
      extractLocal(Buffer.from('<html><body>no title</body></html>'), 'https://x'),
    ).toBeUndefined()
  })

  test('path templates become single-segment wildcards', () => {
    expect(templateToPattern('/repos/{owner}/{repo}/issues')).toBe('/repos/*/*/issues')
    expect(templateToPattern('works/{id}')).toBe('/works/*')
  })

  test('slugify produces a canonical id or nothing', () => {
    expect(slugify('OpenAlex API')).toBe('openalex-api')
    expect(slugify('  Spaces  ')).toBe('spaces')
    expect(slugify('!!!')).toBe('')
  })
})

describe('refresh applies non-conflicting changes and reports conflicts', () => {
  function candidate(fields: Record<string, unknown>, overrides: Partial<RefreshCandidate> = {}) {
    return {
      source: 'public-apis',
      revision: 'abc123',
      content_hash: `v1:sha256:${'a'.repeat(64)}`,
      records: [{ id: 'openalex', fields }],
      ...overrides,
    } as RefreshCandidate
  }

  test('a curated field is left unchanged and reported as a conflict', () => {
    const report = refreshFromCandidate(
      openRoot(repo.root),
      candidate({ description: 'An imported description.' }),
    )
    expect(report.counts.updated).toBe(0)
    expect(report.conflicts).toHaveLength(1)
    expect(report.conflicts[0]?.reason).toBe('curated')
    expect(report.conflicts[0]?.record).toBe('openalex')
    expect(report.conflicts[0]?.field).toBe('description')
    expect(report.conflicts[0]?.proposed).toBe('An imported description.')
    expect(report.files).toEqual([])
  })

  test('a sparse value never blanks a populated one', () => {
    const report = refreshFromCandidate(openRoot(repo.root), candidate({ description: '' }))
    expect(report.conflicts[0]?.reason).toBe('sparse_value')
    expect(report.files).toEqual([])
  })

  test('a field with no recorded provenance is not overwritten', () => {
    const report = refreshFromCandidate(
      openRoot(repo.root),
      candidate({ documentation: 'https://elsewhere.example' }),
    )
    expect(report.counts.updated).toBe(0)
    expect(report.conflicts.some((conflict) => conflict.field === 'documentation')).toBe(true)
  })

  test('a record the catalog does not hold is rejected and applies no change', () => {
    const report = refreshFromCandidate(
      openRoot(repo.root),
      candidate(
        { description: 'x' },
        { records: [{ id: 'unknown-api', fields: { tags: ['a'] } }] },
      ),
    )
    expect(report.ok).toBe(false)
    expect(report.rejections[0]?.id).toBe('unknown-api')
    expect(report.files).toEqual([])
    expect(repo.git('status', '--porcelain')).toBe('')
  })

  test('an unchanged revision and content hash writes no diff', () => {
    const manifest = {
      source_id: 'public-apis',
      name: 'public-apis',
      license: 'MIT',
      revision: 'pinned-abc',
      content_hash: `v1:sha256:${'b'.repeat(64)}`,
      retrieved_at: '2026-01-01T00:00:00Z',
      reason_codes_version: 1,
      counts: { total: 0, imported: 0, aliased: 0, rejected: 0 },
      ledger_hash: `v1:sha256:${'c'.repeat(64)}`,
    }
    repo.writeYaml('catalog/sources/public-apis/manifest.yaml', manifest)
    repo.writeYaml('catalog/sources/public-apis/outcomes.yaml', {
      source_id: 'public-apis',
      reason_codes_version: 1,
      entries: [],
    })
    repo.commit('pin the source')
    const report = refreshFromCandidate(
      openRoot(repo.root),
      candidate({ tags: ['x'] }, { revision: 'pinned-abc', content_hash: manifest.content_hash }),
    )
    expect(report.unchanged_revision).toBe(true)
    expect(report.files).toEqual([])
    expect(repo.git('status', '--porcelain')).toBe('')
  })

  test('an applicable change is written as an uncommitted worktree edit', () => {
    repo.writeYaml('catalog/meta/imported.yaml', {
      id: 'imported',
      name: 'Imported',
      description: 'The original description.',
      curation: 'imported',
      sources: ['public-apis'],
      provenance: {
        description: { source: 'public-apis', last_observed: 'The original description.' },
      },
    })
    repo.commit('add an imported record')
    const head = repo.git('rev-parse', 'HEAD').trim()
    const report = refreshFromCandidate(
      openRoot(repo.root),
      candidate(
        { description: 'A newer description from upstream.' },
        {
          records: [
            { id: 'imported', fields: { description: 'A newer description from upstream.' } },
          ],
        },
      ),
    )
    expect(report.ok).toBe(true)
    expect(report.counts.updated).toBe(1)
    expect(report.files).toEqual([metadataPath('imported')])
    const record = parse(readFileSync(repo.path(metadataPath('imported')), 'utf8')) as {
      description: string
      provenance: Record<string, { last_observed: string }>
    }
    expect(record.description).toBe('A newer description from upstream.')
    expect(record.provenance.description?.last_observed).toBe('A newer description from upstream.')
    expect(repo.git('rev-parse', 'HEAD').trim()).toBe(head)
    expect(repo.git('diff', '--cached', '--name-only')).toBe('')
  })
})

describe('migrate is deterministic and self-validating', () => {
  test('a catalog already at the supported version reports nothing to do', () => {
    const result = migrateCatalog(openRoot(repo.root))
    expect(result.ok).toBe(true)
    expect(result.files).toEqual([])
    expect(repo.git('status', '--porcelain')).toBe('')
  })

  test('two runs from the same starting state produce byte-identical output', () => {
    repo.write(
      'catalog/manifest.yaml',
      readFileSync(repo.path('catalog/manifest.yaml'), 'utf8').replace(
        'schema_version: 1',
        'schema_version: 0',
      ),
    )
    migrateCatalog(openRoot(repo.root))
    const first = new Map<string, string>()
    for (const file of [
      'catalog/manifest.yaml',
      metadataPath('openalex'),
      profilePath('openalex', 'public'),
    ]) {
      first.set(file, readFileSync(repo.path(file), 'utf8'))
    }
    repo.write(
      'catalog/manifest.yaml',
      readFileSync(repo.path('catalog/manifest.yaml'), 'utf8').replace(
        'schema_version: 1',
        'schema_version: 0',
      ),
    )
    migrateCatalog(openRoot(repo.root))
    for (const [file, contents] of first) {
      expect(readFileSync(repo.path(file), 'utf8')).toBe(contents)
    }
  })

  test('a future schema version cannot be migrated downwards', () => {
    repo.write(
      'catalog/manifest.yaml',
      readFileSync(repo.path('catalog/manifest.yaml'), 'utf8').replace(
        'schema_version: 1',
        'schema_version: 99',
      ),
    )
    expect(() => migrateCatalog(openRoot(repo.root))).toThrow('cannot migrate downwards')
  })

  test('a migration whose result would not validate modifies nothing', () => {
    repo.write(
      'catalog/manifest.yaml',
      readFileSync(repo.path('catalog/manifest.yaml'), 'utf8').replace(
        'schema_version: 1',
        'schema_version: 0',
      ),
    )
    repo.writeYaml('catalog/meta/orphan-profile.yaml', {
      id: 'orphan-profile',
      name: 'Orphan',
      profiles: ['nonexistent'],
    })
    expect(() => migrateCatalog(openRoot(repo.root))).toThrow('does not validate')
  })

  test('the migrated catalog validates and leaves the change uncommitted', () => {
    repo.write(
      'catalog/manifest.yaml',
      readFileSync(repo.path('catalog/manifest.yaml'), 'utf8').replace(
        'schema_version: 1',
        'schema_version: 0',
      ),
    )
    const head = repo.git('rev-parse', 'HEAD').trim()
    const result = migrateCatalog(openRoot(repo.root))
    expect(result.from).toBe(0)
    expect(result.to).toBe(1)
    expect(result.files.length).toBeGreaterThan(1)
    expect(validateCatalog(loadWorkingTree(repo.root, openRoot(repo.root).git)).ok).toBe(true)
    expect(repo.git('rev-parse', 'HEAD').trim()).toBe(head)
    expect(repo.git('diff', '--cached', '--name-only')).toBe('')
    expect(repo.git('status', '--porcelain')).toContain('catalog/manifest.yaml')
  })
})

describe('no maintenance command stages, commits, pushes or merges', () => {
  test('add, refresh and migrate all leave the index and refs unchanged', async () => {
    const head = repo.git('rev-parse', 'HEAD').trim()
    const refs = repo.git('show-ref')
    await runAdd(openRoot(repo.root), argv(['Untouched API'], { manual: true }), io, true)
    refreshFromCandidate(openRoot(repo.root), {
      source: 'public-apis',
      revision: 'rev',
      content_hash: `v1:sha256:${'d'.repeat(64)}`,
      records: [],
    })
    migrateCatalog(openRoot(repo.root))
    expect(repo.git('rev-parse', 'HEAD').trim()).toBe(head)
    expect(repo.git('show-ref')).toBe(refs)
    expect(repo.git('diff', '--cached', '--name-only')).toBe('')
  })

  test('no maintenance module invokes a Git mutation', async () => {
    for (const module of ['commands', 'fetch', 'extract', 'apply']) {
      const source = await Bun.file(
        Bun.fileURLToPath(new URL(`../../src/maintenance/${module}.ts`, import.meta.url)),
      ).text()
      for (const mutation of ["'add'", "'commit'", "'push'", "'merge'", "'stage'"]) {
        expect(`${module}:${source.includes(mutation)}`).toBe(`${module}:false`)
      }
    }
  })
})

describe('the tracked catalog is never mutated by a read command', () => {
  test('validate, search and show create, modify or delete no catalog file', () => {
    const before = repo.git('status', '--porcelain')
    validateCatalog(loadWorkingTree(repo.root, openRoot(repo.root).git))
    expect(repo.git('status', '--porcelain')).toBe(before)
    expect(existsSync(repo.path('catalog/manifest.yaml'))).toBe(true)
  })

  test('writing a candidate does not touch an unrelated record', async () => {
    const before = readFileSync(repo.path(metadataPath('openalex')), 'utf8')
    await runAdd(openRoot(repo.root), argv(['Side Effect Check'], { manual: true }), io, true)
    expect(readFileSync(repo.path(metadataPath('openalex')), 'utf8')).toBe(before)
  })
})

describe('derived state can be discarded and rebuilt', () => {
  test('a catalog reloaded from YAML answers identically', () => {
    const root = openRoot(repo.root)
    const first = loadWorkingTree(root.path, root.git)
    const second = loadWorkingTree(root.path, root.git)
    expect([...second.records.keys()]).toEqual([...first.records.keys()])
    expect(stringify([...second.profiles.keys()])).toBe(stringify([...first.profiles.keys()]))
  })
})
