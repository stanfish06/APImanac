import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { GrantStore } from '../../src/auth/grants'
import { HealthStore } from '../../src/execute/health'
import {
  formatShownRecord,
  OPERATION_LIMIT,
  SPEC_SUMMARY_LIMIT,
  showRecord,
} from '../../src/search/show'
import { openRoot, starterCatalogRepo } from '../helpers/catalog'
import type { TempRepo } from '../helpers/repo'

let repo: TempRepo
let scratch: string

beforeEach(() => {
  repo = starterCatalogRepo()
  repo.commit('seed catalog')
  scratch = mkdtempSync(join(tmpdir(), 'apimanac-show-'))
})

afterEach(() => {
  repo.dispose()
  rmSync(scratch, { recursive: true, force: true })
})

function show(requested: string, health?: HealthStore) {
  return showRecord(openRoot(repo.root), requested, {
    grants: GrantStore.load({ path: join(scratch, 'grants.yaml') }),
    health,
  })
}

describe('inspection reports identity, trust and both hashes', () => {
  test('a canonical id resolves and reports every profile', () => {
    const record = show('ncbi-eutils')
    expect(record?.id).toBe('ncbi-eutils')
    expect(record?.profiles.map((profile) => profile.profile_id).sort()).toEqual([
      'keyed',
      'public',
    ])
  })

  test('reviewer-attached resources are reported and rendered with their descriptions', () => {
    const record = show('openalex')
    expect(record?.resources).toEqual([
      {
        url: 'https://docs.openalex.org/how-to-use-the-api/get-lists-of-entities/filter-entity-lists',
        description: 'Filter syntax reference for list endpoints',
      },
    ])
    const text = formatShownRecord(record!)
    expect(text).toContain('resources:')
    expect(text).toContain(
      'https://docs.openalex.org/how-to-use-the-api/get-lists-of-entities/filter-entity-lists  Filter syntax reference for list endpoints',
    )
    expect(show('ncbi-eutils')?.resources).toEqual([])
  })

  test('an alias resolves and the alias used is reported', () => {
    const record = show('eutils')
    expect(record?.id).toBe('ncbi-eutils')
    expect(record?.matched_alias).toBe('eutils')
  })

  test('an unknown id yields nothing rather than a partial record', () => {
    expect(show('nope')).toBeUndefined()
  })

  test('the contract hash and the authority fingerprint are both printed', () => {
    const record = show('github')
    const profile = record?.profiles[0]
    expect(profile?.contract_hash).toMatch(/^v1:sha256:[0-9a-f]{64}$/)
    expect(profile?.authority_fingerprint).toMatch(/^v1:sha256:[0-9a-f]{64}$/)
    expect(profile?.contract_hash).not.toBe(profile?.authority_fingerprint)
    const text = formatShownRecord(record!)
    expect(text).toContain(profile?.authority_fingerprint as string)
    expect(text).not.toContain('credential value')
  })

  test('permission decisions are reported per operation', () => {
    const record = show('github')
    const operations = record?.profiles[0]?.operations ?? []
    expect(operations.some((operation) => operation.decision === 'confirm')).toBe(true)
    expect(operations.some((operation) => operation.decision === 'deny')).toBe(true)
  })

  test('a candidate profile reports why it is ineligible', () => {
    const record = show('openalex')
    const profile = record?.profiles[0]
    expect(profile?.verification).toBe('candidate')
    expect(profile?.eligible).toBe(false)
    expect(profile?.ineligible_reason).toContain('apimanac verify')
  })
})

describe('health is reported separately from the catalog verified_at', () => {
  test('an unobserved profile reports unknown with no last_checked', () => {
    const health = HealthStore.open(join(scratch, 'health.db'))
    try {
      const profile = show('openalex', health)?.profiles[0]
      expect(profile?.health).toBe('unknown')
      expect(profile?.health_last_checked).toBeUndefined()
    } finally {
      health.close()
    }
  })

  test('an observed profile reports last_checked distinctly from verified_at', () => {
    const health = HealthStore.open(join(scratch, 'health.db'))
    try {
      health.record('openalex', 'public', { status: 429 }, new Date('2026-05-01T00:00:00Z'))
      const profile = show('openalex', health)?.profiles[0]
      expect(profile?.health).toBe('rate_limited')
      expect(profile?.health_last_checked).toBe('2026-05-01T00:00:00.000Z')
      // The seed profile is a candidate, so it carries no verified_at at all.
      expect(profile?.verified_at).toBeUndefined()
      expect(profile?.health_last_checked).not.toBe(profile?.verified_at)
    } finally {
      health.close()
    }
  })

  test('the human output labels both times distinctly', () => {
    const health = HealthStore.open(join(scratch, 'health.db'))
    try {
      health.record('crossref', 'public', { status: 200 }, new Date('2026-05-02T00:00:00Z'))
      const text = formatShownRecord(show('crossref', health)!)
      expect(text).toContain('health: healthy (last checked 2026-05-02T00:00:00.000Z)')
      expect(text).toContain('verification: candidate')
    } finally {
      health.close()
    }
  })
})

describe('output is bounded', () => {
  test('operations are capped and the truncation is reported', () => {
    const rules = Array.from({ length: OPERATION_LIMIT + 5 }, (_, index) => ({
      method: 'GET',
      path: `/route-${index}`,
      decision: 'auto',
    }))
    repo.writeYaml('catalog/meta/wide.yaml', { id: 'wide', name: 'Wide', profiles: ['public'] })
    repo.writeYaml('catalog/execution/wide/public.yaml', {
      profile_id: 'public',
      api_id: 'wide',
      origins: ['https://api.wide.example'],
      auth: { type: 'none' },
      permissions: rules,
    })
    const profile = show('wide')?.profiles[0]
    expect(profile?.operations).toHaveLength(OPERATION_LIMIT)
    expect(profile?.operations_truncated).toBe(true)
    expect(formatShownRecord(show('wide')!)).toContain('more operations not shown')
  })

  test('a large specification yields a bounded summary and a reference, not the document', () => {
    const summary = 'x'.repeat(SPEC_SUMMARY_LIMIT * 3)
    repo.writeYaml('catalog/meta/specced.yaml', {
      id: 'specced',
      name: 'Specced',
      profiles: ['public'],
    })
    repo.writeYaml('catalog/execution/specced/public.yaml', {
      profile_id: 'public',
      api_id: 'specced',
      origins: ['https://api.specced.example'],
      auth: { type: 'none' },
      spec_ref: {
        id: 'huge',
        url: 'https://api.specced.example/openapi.json',
        format: 'openapi-3',
        byte_size: 7_340_032,
        summary,
      },
    })
    const spec = show('specced')?.profiles[0]?.spec
    expect(spec?.url).toBe('https://api.specced.example/openapi.json')
    expect(spec?.byte_size).toBe(7_340_032)
    expect((spec?.summary ?? '').length).toBeLessThanOrEqual(SPEC_SUMMARY_LIMIT + 1)
    expect(spec?.summary).not.toBe(summary)
  })

  test('a draft record and a draft profile are both labeled', () => {
    repo.writeYaml('catalog/meta/openalex.yaml', {
      id: 'openalex',
      name: 'OpenAlex edited',
      profiles: ['public'],
    })
    const record = show('openalex')
    expect(record?.draft).toBe(true)
    expect(formatShownRecord(record!)).toContain('draft')
  })
})

describe('callable and auth_supported are distinct predicates', () => {
  test('a candidate with a supported auth shape is auth_supported but not callable', () => {
    const record = show('openalex')
    // The seed profiles ship as candidates, so nothing is callable yet.
    expect(record?.auth_supported).toBe(true)
    expect(record?.callable).toBe(false)
    expect(record?.profiles[0]?.auth_supported).toBe(true)
    expect(record?.profiles[0]?.eligible).toBe(false)
  })

  test('neither surface still uses the ambiguous `executable` name', () => {
    const record = show('openalex')
    expect(Object.keys(record ?? {})).not.toContain('executable')
    expect(Object.keys(record?.profiles[0] ?? {})).not.toContain('executable')
  })

  test('an unsupported auth type is neither auth_supported nor callable', () => {
    repo.writeYaml('catalog/meta/oauthonly.yaml', {
      id: 'oauthonly',
      name: 'OAuth only',
      profiles: ['flow'],
    })
    repo.writeYaml('catalog/execution/oauthonly/flow.yaml', {
      profile_id: 'flow',
      api_id: 'oauthonly',
      origins: ['https://api.oauthonly.example'],
      auth: { type: 'oauth2', credential_id: 'oauthonly', components: [{ name: 'access_token' }] },
    })
    const record = show('oauthonly')
    expect(record?.auth_supported).toBe(false)
    expect(record?.callable).toBe(false)
  })
})
