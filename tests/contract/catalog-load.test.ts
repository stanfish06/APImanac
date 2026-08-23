import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { buildIdentityIndex } from '../../src/catalog/identity'
import { loadCommitted, loadWorkingTree } from '../../src/catalog/load'
import { planFieldUpdates, upstreamDisappearance } from '../../src/catalog/provenance'
import { validateCatalog } from '../../src/catalog/validate'
import { MetadataRecord } from '../../src/schema/metadata'
import { openRoot, starterCatalogRepo } from '../helpers/catalog'
import { TempRepo, fixtureManifest } from '../helpers/repo'

function record(id: string, extra: Record<string, unknown> = {}): unknown {
  return { id, name: id, ...extra }
}

describe('working-tree loading labels drafts', () => {
  let repo: TempRepo

  beforeEach(() => {
    repo = TempRepo.create()
    repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
    repo.writeYaml('catalog/meta/committed.yaml', record('committed'))
    repo.commit('seed')
  })

  afterEach(() => repo.dispose())

  test('a committed, unmodified record is not a draft', () => {
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    expect(snapshot.records.get('committed')?.draft).toBe(false)
    expect(snapshot.records.get('committed')?.state).toBe('tracked_clean')
  })

  test('an untracked record loads labeled a draft', () => {
    repo.writeYaml('catalog/meta/fresh.yaml', record('fresh'))
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    expect(snapshot.records.get('fresh')?.draft).toBe(true)
    expect(snapshot.records.get('fresh')?.state).toBe('untracked')
  })

  test('a modified record loads labeled a draft with the working-tree content', () => {
    repo.writeYaml('catalog/meta/committed.yaml', record('committed', { description: 'edited' }))
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    const entry = snapshot.records.get('committed')
    expect(entry?.draft).toBe(true)
    expect(entry?.state).toBe('tracked_modified')
    expect(entry?.value.description).toBe('edited')
  })

  test('a deleted record still appears, labeled deleted', () => {
    repo.remove('catalog/meta/committed.yaml')
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    // The worktree file is gone, so only the committed loader can read it.
    expect(root.git.pathState('catalog/meta/committed.yaml')).toBe('tracked_deleted')
    expect(loadCommitted(root.git).records.get('committed')).toBeDefined()
    expect(snapshot.records.get('committed')).toBeUndefined()
  })
})

describe('committed loading ignores the working tree', () => {
  let repo: TempRepo

  beforeEach(() => {
    repo = TempRepo.create()
    repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
    repo.writeYaml('catalog/meta/api.yaml', record('api', { description: 'committed text' }))
    repo.commit('seed')
  })

  afterEach(() => repo.dispose())

  test('a worktree edit does not change what the committed loader returns', () => {
    repo.writeYaml('catalog/meta/api.yaml', record('api', { description: 'worktree text' }))
    const root = openRoot(repo.root)
    expect(loadCommitted(root.git).records.get('api')?.value.description).toBe('committed text')
    expect(loadWorkingTree(root.path, root.git).records.get('api')?.value.description).toBe(
      'worktree text',
    )
  })

  test('an untracked record is absent from the committed snapshot', () => {
    repo.writeYaml('catalog/meta/draft.yaml', record('draft'))
    const root = openRoot(repo.root)
    expect(loadCommitted(root.git).records.has('draft')).toBe(false)
    expect(loadWorkingTree(root.path, root.git).records.has('draft')).toBe(true)
  })
})

describe('identity resolution', () => {
  function indexOf(records: unknown[]) {
    const map = new Map(
      records.map((raw) => {
        const parsed = MetadataRecord.parse(raw)
        return [
          parsed.id,
          {
            file: `catalog/meta/${parsed.id}.yaml`,
            value: parsed,
            state: 'tracked_clean' as const,
            draft: false,
          },
        ]
      }),
    )
    return buildIdentityIndex(map)
  }

  test('a lookup by alias resolves to the canonical record and reports the alias', () => {
    const index = indexOf([record('openalex', { aliases: ['open-alex'] })])
    const resolution = index.resolve('open-alex')
    expect(resolution?.id).toBe('openalex')
    expect(resolution?.viaAlias).toBe('open-alex')
  })

  test('a lookup by a merged id resolves to the target and reports the redirect', () => {
    const index = indexOf([
      record('target'),
      record('old', { lifecycle: 'merged', merged_into: 'target' }),
    ])
    const resolution = index.resolve('old')
    expect(resolution?.id).toBe('target')
    expect(resolution?.viaMerge).toEqual(['old', 'target'])
  })

  test('a merge cycle fails validation naming the chain', () => {
    const index = indexOf([
      record('one', { lifecycle: 'merged', merged_into: 'two' }),
      record('two', { lifecycle: 'merged', merged_into: 'one' }),
    ])
    const cycle = index.issues.find((issue) => issue.kind === 'merge_cycle')
    expect(cycle).toBeDefined()
    expect(cycle?.message).toContain('one -> two -> one')
  })

  test('a dangling merge target fails validation naming the chain', () => {
    const index = indexOf([record('orphan', { lifecycle: 'merged', merged_into: 'nowhere' })])
    const dangling = index.issues.find((issue) => issue.kind === 'merge_dangling')
    expect(dangling?.message).toContain('orphan -> nowhere')
  })

  test('an alias claimed by two records fails validation naming every file', () => {
    const index = indexOf([
      record('alpha', { aliases: ['shared'] }),
      record('beta', { aliases: ['shared'] }),
    ])
    const collision = index.issues.find((issue) => issue.kind === 'alias_collision')
    expect(collision?.message).toContain('catalog/meta/alpha.yaml')
    expect(collision?.message).toContain('catalog/meta/beta.yaml')
  })

  test('an alias equal to another record’s canonical id fails validation', () => {
    const index = indexOf([record('alpha', { aliases: ['beta'] }), record('beta')])
    expect(index.issues.some((issue) => issue.kind === 'alias_collision')).toBe(true)
  })

  test('two records sharing a homepage domain stay distinct', () => {
    const index = indexOf([
      record('one', { homepage: 'https://shared.example' }),
      record('two', { homepage: 'https://shared.example' }),
    ])
    expect(index.ids()).toEqual(['one', 'two'])
    expect(index.issues).toEqual([])
  })

  test('a same_as proposal does not change resolution', () => {
    const index = indexOf([record('one', { same_as: ['two'] }), record('two')])
    expect(index.resolve('one')?.id).toBe('one')
  })

  test('an unknown id resolves to nothing', () => {
    expect(indexOf([record('one')]).resolve('nope')).toBeUndefined()
  })
})

describe('field update rules', () => {
  const stored = MetadataRecord.parse({
    id: 'api',
    name: 'API',
    description: 'A rich description supplied by public-apis.',
    categories: ['research'],
    provenance: {
      description: {
        source: 'public-apis',
        last_observed: 'A rich description supplied by public-apis.',
      },
      categories: { source: 'nango', last_observed: 'research' },
    },
  })

  test('an empty source value leaves a populated field unchanged and reports a conflict', () => {
    const outcome = planFieldUpdates(stored, 'public-apis', { description: '' })
    expect(outcome.updates).toEqual([])
    expect(outcome.conflicts).toHaveLength(1)
    expect(outcome.conflicts[0]?.reason).toBe('sparse_value')
    expect(outcome.conflicts[0]?.field).toBe('description')
  })

  test('an empty array does not clear a populated array', () => {
    const outcome = planFieldUpdates(stored, 'nango', { categories: [] })
    expect(outcome.updates).toEqual([])
    expect(outcome.conflicts[0]?.reason).toBe('sparse_value')
  })

  test('a source may update the field it owns while the value still matches', () => {
    const outcome = planFieldUpdates(stored, 'public-apis', { description: 'A newer description.' })
    expect(outcome.conflicts).toEqual([])
    expect(outcome.updates[0]?.field).toBe('description')
  })

  test('another source proposing a different value is a conflict', () => {
    const outcome = planFieldUpdates(stored, 'apis-guru', { description: 'Something else.' })
    expect(outcome.updates).toEqual([])
    expect(outcome.conflicts[0]?.reason).toBe('owned_by_other_source')
    expect(outcome.conflicts[0]?.current).toContain('public-apis')
    expect(outcome.conflicts[0]?.proposed).toBe('Something else.')
  })

  test('a curated field is never overwritten', () => {
    const curated = MetadataRecord.parse({
      id: 'api',
      name: 'API',
      description: 'Hand-written.',
      provenance: { description: { source: 'manual', curated: true } },
    })
    const outcome = planFieldUpdates(curated, 'public-apis', { description: 'Imported.' })
    expect(outcome.updates).toEqual([])
    expect(outcome.conflicts[0]?.reason).toBe('curated')
  })

  test('a value that diverged from the last observed one is left alone', () => {
    const diverged = MetadataRecord.parse({
      id: 'api',
      name: 'API',
      description: 'Edited by hand since the last import.',
      provenance: { description: { source: 'public-apis', last_observed: 'Original.' } },
    })
    const outcome = planFieldUpdates(diverged, 'public-apis', { description: 'Newer.' })
    expect(outcome.updates).toEqual([])
    expect(outcome.conflicts[0]?.reason).toBe('diverged_from_last_observed')
  })

  test('an upstream disappearance leaves the lifecycle unchanged', () => {
    const conflict = upstreamDisappearance(stored, 'public-apis')
    expect(conflict.current).toBe('active')
    expect(conflict.proposed).toBe('active')
    expect(conflict.reason).toBe('upstream_disappeared')
  })
})

describe('validate over the shipped seed catalog', () => {
  let repo: TempRepo

  beforeEach(() => {
    repo = starterCatalogRepo()
    repo.commit('seed catalog')
  })

  afterEach(() => repo.dispose())

  test('reports no findings', () => {
    const root = openRoot(repo.root)
    const report = validateCatalog(loadWorkingTree(root.path, root.git))
    expect(report.findings.map((f) => `${f.kind} ${f.file} ${f.message}`)).toEqual([])
    expect(report.ok).toBe(true)
  })

  test('all five curated records and their profiles parse', () => {
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    expect([...snapshot.records.keys()].sort()).toEqual([
      'crossref',
      'datacite',
      'github',
      'ncbi-eutils',
      'openalex',
    ])
    expect([...snapshot.profiles.keys()].sort()).toEqual([
      'crossref/public',
      'datacite/public',
      'github/pat',
      'ncbi-eutils/keyed',
      'ncbi-eutils/public',
      'openalex/public',
    ])
  })

  test('every seed profile is a candidate, so nothing ships executable', () => {
    const root = openRoot(repo.root)
    for (const entry of loadWorkingTree(root.path, root.git).profiles.values()) {
      expect(entry.value.verification.state).toBe('candidate')
    }
  })

  test('a helper-created profile reports as tracked and clean', () => {
    const root = openRoot(repo.root)
    expect(root.git.pathState('catalog/execution/openalex/public.yaml')).toBe('tracked_clean')
    const blob = root.git.readHeadBlob('catalog/execution/openalex/public.yaml')
    expect(blob.present).toBe(true)
    expect(
      blob.bytes?.equals(readFileSync(repo.path('catalog/execution/openalex/public.yaml'))),
    ).toBe(true)
  })
})
