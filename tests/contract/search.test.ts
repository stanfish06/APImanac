import { cpSync, mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import {
  BenchmarkFile,
  REQUIRED_HITS,
  formatBenchmark,
  runBenchmark,
} from '../../src/search/benchmark'
import { CatalogQuery, validateFilters } from '../../src/search/query'
import { buildStore } from '../../src/store/build'
import { openStore } from '../../src/store/open'
import { openRoot } from '../helpers/catalog'
import { TempRepo } from '../helpers/repo'
import { fixturePath, loadFixture } from '../helpers/yaml'

let repo: TempRepo
let cacheDir: string
let storePath: string
let catalog: CatalogQuery
let close: () => void

beforeAll(() => {
  repo = TempRepo.create()
  cpSync(fixturePath('search', 'catalog'), repo.path('catalog'), { recursive: true })
  repo.commit('search fixture catalog')
  cacheDir = mkdtempSync(join(tmpdir(), 'apimanac-search-'))
  storePath = join(cacheDir, 'catalog.db')
  buildStore(openRoot(repo.root), { storePath })
  const opened = openStore(openRoot(repo.root), { storePath })
  catalog = new CatalogQuery(opened.db)
  close = opened.close
})

afterAll(() => {
  close()
  repo.dispose()
  rmSync(cacheDir, { recursive: true, force: true })
})

describe('result payloads', () => {
  test('carry identity, trust, readiness and health and no endpoints or credentials', () => {
    const result = catalog.search('openalex').results[0]
    expect(result?.id).toBe('openalex')
    expect(result?.curation).toBe('curated')
    expect(result?.lifecycle).toBe('active')
    expect(result?.verification).toBe('verified')
    expect(result?.readiness).toBe('not_required')
    expect(result?.health).toBe('unknown')
    expect(result?.sources).toEqual(['manual'])
    const serialized = JSON.stringify(result)
    expect(serialized).not.toContain('api.openalex.org')
    expect(serialized).not.toContain('/works/**')
    expect(serialized).not.toContain('credential')
  })

  test('a record with no execution profile reports no supported auth shape', () => {
    const result = catalog.search('defunct-directory').results[0]
    expect(result?.auth_supported).toBe(false)
    expect(result?.profile_count).toBe(0)
  })

  test('a record with lifecycle gone is returned labeled rather than omitted', () => {
    const result = catalog.search('directory listing service').results
    expect(
      result.some((entry) => entry.id === 'defunct-directory' && entry.lifecycle === 'gone'),
    ).toBe(true)
  })

  test('a record whose only profile uses an unsupported auth type reports so', () => {
    const result = catalog.search('slack').results[0]
    expect(result?.auth_supported).toBe(false)
    expect(result?.readiness).toBe('unsupported_auth')
  })

  test('search reports auth capability, never callability', () => {
    // A candidate profile with a supported auth shape: search says the shape is
    // runnable, and deliberately does not claim a call would go through.
    const result = catalog.search('openalex').results[0]
    expect(result?.auth_supported).toBe(true)
    expect(Object.keys(result ?? {})).not.toContain('executable')
    expect(Object.keys(result ?? {})).not.toContain('callable')
  })

  test('readiness is not_required for a no-auth profile', () => {
    expect(catalog.search('wikipedia').results[0]?.readiness).toBe('not_required')
  })

  test('a record with a credential-requiring profile and no grant reports no_grant', () => {
    expect(catalog.search('github').results[0]?.readiness).toBe('no_grant')
  })
})

describe('ranking', () => {
  test('an exact canonical id is the first result', () => {
    expect(catalog.search('openalex').results[0]?.id).toBe('openalex')
    expect(catalog.search('openalex').results[0]?.exact).toBe(true)
  })

  test('an exact alias is the first result and reports the alias', () => {
    const first = catalog.search('api-github-com').results[0]
    expect(first?.id).toBe('github')
    expect(first?.matched_alias).toBe('api-github-com')
  })

  test('a merged id collapses into its target and reports the redirect', () => {
    const first = catalog.search('old-pubmed-api').results[0]
    expect(first?.id).toBe('ncbi-eutils')
    expect(first?.redirected_from).toBe('old-pubmed-api')
  })

  test('a query matching a merged record and its target returns one result', () => {
    const results = catalog.search('pubmed').results
    expect(results.filter((entry) => entry.id === 'old-pubmed-api')).toHaveLength(0)
    expect(results.some((entry) => entry.id === 'ncbi-eutils')).toBe(true)
  })

  test('a name match outranks a description-only match', () => {
    const results = catalog.search('wikidata').results.map((entry) => entry.id)
    expect(results[0]).toBe('wikidata')
  })

  test('the same query twice returns an identical order', () => {
    const first = catalog.search('citation counts').results.map((entry) => entry.id)
    const second = catalog.search('citation counts').results.map((entry) => entry.id)
    expect(second).toEqual(first)
  })

  test('a curated record outranks an imported one that ties on text', () => {
    const results = catalog.search('bibliographic metadata journals').results.map((e) => e.id)
    expect(results.indexOf('crossref')).toBeLessThan(results.indexOf('semantic-scholar'))
  })

  test('a verified profile outranks a candidate that ties on text', () => {
    const results = catalog.search('version control repository issues').results.map((e) => e.id)
    expect(results.indexOf('github')).toBeLessThan(results.indexOf('gitlab'))
  })
})

describe('filters', () => {
  test('filtering by curation narrows to curated records', () => {
    const results = catalog.search('', { filters: { curation: 'curated' }, limit: 50 }).results
    expect(results.length).toBeGreaterThan(0)
    expect(results.every((entry) => entry.curation === 'curated')).toBe(true)
  })

  test('filtering to a verified, ready execution profile narrows correctly', () => {
    const results = catalog.search('', {
      filters: { verification: 'verified', readiness: 'not_required' },
      limit: 50,
    }).results
    expect(results.map((entry) => entry.id).sort()).toEqual([
      'crossref',
      'openalex',
      'semantic-scholar',
      'wikipedia',
    ])
  })

  test('combined source and auth-type filters return only records satisfying both', () => {
    const results = catalog.search('', {
      filters: { source: 'nango', auth_type: 'bearer' },
      limit: 50,
    }).results
    expect(results.map((entry) => entry.id)).toEqual(['stripe'])
  })

  test('filtering by lifecycle and health works', () => {
    expect(
      catalog.search('', { filters: { lifecycle: 'gone' }, limit: 50 }).results.map((e) => e.id),
    ).toEqual(['defunct-directory'])
    expect(catalog.search('', { filters: { health: 'healthy' }, limit: 50 }).results).toHaveLength(
      0,
    )
  })

  test('filtering by category or tag narrows results', () => {
    const byCategory = catalog.search('', { filters: { category: 'weather' }, limit: 50 }).results
    expect(byCategory.map((e) => e.id)).toEqual(['openweathermap'])
    const byTag = catalog.search('', { filters: { tag: 'sparql' }, limit: 50 }).results
    expect(byTag.map((e) => e.id)).toEqual(['wikidata'])
  })

  test('an unknown filter value is a typed error naming the filter and allowed values', () => {
    expect(() => validateFilters({ curation: 'excellent' })).toThrow('is not an allowed value')
    try {
      validateFilters({ health: 'fine' })
    } catch (error) {
      const detail = (error as { detail: Record<string, unknown> }).detail
      expect(detail.filter).toBe('health')
      expect(detail.allowed).toContain('degraded')
    }
  })

  test('an unknown filter value returns no results because the query never runs', () => {
    let ran = false
    try {
      validateFilters({ lifecycle: 'zombie' })
      ran = true
    } catch {
      ran = false
    }
    expect(ran).toBe(false)
  })
})

describe('the committed benchmark', () => {
  test('the fixture parses and every expected id exists in the fixture catalog', () => {
    const fixture = BenchmarkFile.parse(loadFixture('search', 'queries.yaml'))
    const known = new Set(catalog.search('', { limit: 50 }).results.map((entry) => entry.id))
    for (const query of fixture.queries) {
      for (const id of query.relevant) {
        expect(`${query.id}:${id}:${known.has(id)}`).toBe(`${query.id}:${id}:true`)
      }
    }
    for (const entry of fixture.exact) {
      expect(`${entry.query}:${known.has(entry.expect)}`).toBe(`${entry.query}:true`)
    }
  })

  test('at least 16 of 20 queries return a relevant top-five result', () => {
    const fixture = BenchmarkFile.parse(loadFixture('search', 'queries.yaml'))
    const report = runBenchmark(catalog, fixture)
    if (!report.ok) console.log(formatBenchmark(report))
    expect(report.hits).toBeGreaterThanOrEqual(REQUIRED_HITS)
  })

  test('every exact id or alias lookup fixture resolves', () => {
    const fixture = BenchmarkFile.parse(loadFixture('search', 'queries.yaml'))
    const report = runBenchmark(catalog, fixture)
    const failures = report.exact.filter((outcome) => !outcome.ok)
    expect(failures.map((f) => `${f.query} -> ${f.actual}`)).toEqual([])
  })
})
