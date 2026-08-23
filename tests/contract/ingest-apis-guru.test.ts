import { describe, expect, test } from 'bun:test'
import { buildLedger, type SourcePin } from '../../src/ingest/adapter'
import { apisGuruAdapter, runApisGuru } from '../../src/ingest/apis-guru'
import { MUTATING_METHODS } from '../../src/policy/permissions'
import { ExecutionProfile } from '../../src/schema/execution'
import { MetadataRecord } from '../../src/schema/metadata'
import { OutcomeLedger } from '../../src/schema/report'
import { fixturePath, loadFixture } from '../helpers/yaml'

const pin = (() => {
  const value = loadFixture('sources', 'apis-guru', 'pin.yaml') as Record<string, string>
  return {
    revision: value.revision ?? '',
    contentHash: value.content_hash ?? '',
    retrievedAt: value.retrieved_at ?? '',
  } satisfies SourcePin
})()

/**
 * Each fixture file is named for the upstream list id it belongs to, with `/`
 * written as `__` — the same convention `apimanac refresh --specs` reads. Keying
 * by anything else silently drops the entries whose id is not a bare slug.
 */
function specs(): Map<string, unknown> {
  const directory = fixturePath('sources', 'apis-guru', 'specs')
  const entries = [...new Bun.Glob('*.json').scanSync({ cwd: directory })].sort()
  return new Map(
    entries.map((file) => [
      file.replace(/\.json$/, '').replaceAll('__', '/'),
      loadFixture('sources', 'apis-guru', 'specs', file),
    ]),
  )
}

function run(limits?: { maxBytes: number }) {
  return runApisGuru(
    loadFixture('sources', 'apis-guru', 'list.json'),
    pin,
    specs(),
    limits ?? { maxBytes: 2_000_000 },
  )
}

function profiles() {
  return new Map(run().execution.map((c) => [c.sourceEntryId, ExecutionProfile.parse(c.profile)]))
}

function rejections() {
  return new Map(run().rejections.map((r) => [r.sourceEntryId, r]))
}

describe('apis-guru adapter', () => {
  test('a list entry with no fetched specification invents no origin', () => {
    const result = run()
    const record = result.metadata.find((c) => c.sourceEntryId === 'weathermap')
    expect(record).toBeTruthy()
    expect(MetadataRecord.parse(record?.record).profiles).toEqual([])
    expect(result.execution.some((c) => c.sourceEntryId === 'weathermap')).toBe(false)
    expect(rejections().has('weathermap')).toBe(false)
  })

  test('a swagger 2.0 host, basePath and schemes triple converts to origins and a base path', () => {
    const profile = profiles().get('petstore')
    expect(profile?.origins).toEqual([
      'https://petstore.example.com',
      'http://petstore.example.com',
    ])
    expect(profile?.base_path).toBe('/v2')
    expect(profile?.spec_ref?.format).toBe('swagger-2')
  })

  test('read operations become auto rules and the mutating methods are denied', () => {
    const profile = profiles().get('petstore')
    expect(profile?.permissions).toEqual([
      { method: 'GET', path: '/pets', decision: 'auto' },
      { method: 'GET', path: '/pets/*', decision: 'auto' },
      ...MUTATING_METHODS.map((method) => ({ method, path: '/**', decision: 'deny' as const })),
    ])
  })

  test('an openapi 3 server path becomes the base path, never part of the origin', () => {
    const profile = profiles().get('googleapis.com:drive')
    expect(profile?.origins).toEqual(['https://www.googleapis.com'])
    expect(profile?.base_path).toBe('/drive/v3')
  })

  test('an oauth2 scheme stays describable and declares no placement', () => {
    const profile = profiles().get('googleapis.com:drive')
    expect(profile?.auth.type).toBe('oauth2')
    expect(profile?.auth.placements).toEqual([])
    expect(profile?.auth.scopes.length).toBe(2)
  })

  test('a specification with no security scheme yields no auth', () => {
    expect(profiles().get('openalex.org')?.auth.type).toBe('none')
  })

  test('a non-conforming raw id becomes an alias with a conforming id proposed', () => {
    const result = run()
    const record = MetadataRecord.parse(
      result.metadata.find((c) => c.sourceEntryId === 'openalex.org')?.record,
    )
    expect(record.id).toBe('openalex-org')
    expect(record.aliases).toEqual(['apis-guru:openalex.org'])
    const ledger = OutcomeLedger.parse(buildLedger(result))
    const entry = ledger.entries.find((e) => e.source_entry_id === 'openalex.org')
    expect(entry?.outcome).toBe('imported')
    if (entry?.outcome === 'imported') expect(entry.api_id).toBe('openalex-org')

    const drive = MetadataRecord.parse(
      result.metadata.find((c) => c.sourceEntryId === 'googleapis.com:drive')?.record,
    )
    expect(drive.id).toBe('googleapis-com-drive')
    expect(drive.aliases).toEqual(['apis-guru:googleapis.com:drive'])
  })

  test('an oversized specification rejects and no partial parse result is used', () => {
    const result = run()
    expect(rejections().get('bigapi')?.reasonCode).toBe('spec_too_large')
    expect(result.metadata.some((c) => c.sourceEntryId === 'bigapi')).toBe(false)
    expect(result.execution.some((c) => c.sourceEntryId === 'bigapi')).toBe(false)
  })

  test('the byte limit applies to a specification that was fetched whole', () => {
    const tight = run({ maxBytes: 200 })
    const rejected = new Map(tight.rejections.map((r) => [r.sourceEntryId, r.reasonCode]))
    expect(rejected.get('petstore')).toBe('spec_too_large')
    expect(tight.execution.some((c) => c.sourceEntryId === 'petstore')).toBe(false)
  })

  test('the remaining rejections cite their declared codes', () => {
    const rejected = rejections()
    expect(rejected.get('noversions')?.reasonCode).toBe('no_preferred_version')
    expect(rejected.get('nospecurl')?.reasonCode).toBe('missing_spec_url')
    expect(rejected.get('garbled')?.reasonCode).toBe('spec_unparseable')
    expect(rejected.get('legacy')?.reasonCode).toBe('unsupported_spec_version')
    expect(rejected.get('noservers')?.reasonCode).toBe('no_servers_in_spec')
    for (const rejection of rejected.values()) {
      expect(apisGuruAdapter.reasons.codes).toContain(rejection.reasonCode)
    }
  })

  test('a specification is referenced, never inlined', () => {
    for (const candidate of run().execution) {
      const profile = ExecutionProfile.parse(candidate.profile)
      const ref = profile.spec_ref
      expect(ref?.url).toMatch(/^https:\/\//)
      expect((ref?.summary ?? '').length).toBeLessThanOrEqual(2000)
      expect(JSON.stringify(profile)).not.toContain('operationId')
    }
  })

  test('derived permission rules are capped and the cap is noted', () => {
    const paths: Record<string, unknown> = {}
    for (let i = 0; i < 60; i++) paths[`/thing${i}`] = { get: { operationId: `get${i}` } }
    const list = {
      wide: {
        preferred: '1.0.0',
        versions: {
          '1.0.0': {
            swaggerUrl: 'https://api.apis.guru/v2/specs/wide/1.0.0/openapi.json',
            info: { title: 'Wide', version: '1.0.0' },
          },
        },
      },
    }
    const spec = {
      openapi: '3.0.0',
      info: { title: 'Wide', version: '1.0.0' },
      servers: [{ url: 'https://api.wide.example' }],
      paths,
    }
    const result = runApisGuru(list, pin, new Map([['wide', spec]]))
    const profile = ExecutionProfile.parse(result.execution[0]?.profile)
    expect(profile.permissions.filter((rule) => rule.decision === 'auto').length).toBe(50)
    // A `*`-method catch-all would deny the auto rules above, so each mutating
    // method is denied on its own.
    expect(profile.permissions.slice(-4)).toEqual(
      MUTATING_METHODS.map((method) => ({ method, path: '/**', decision: 'deny' as const })),
    )
    expect(profile.description).toContain('capped at 50')
  })

  test('every candidate parses and every profile is a candidate owned by apis-guru', () => {
    const result = run()
    for (const candidate of result.metadata) {
      const record = MetadataRecord.parse(candidate.record)
      expect(record.sources).toEqual(['apis-guru'])
    }
    for (const candidate of result.execution) {
      const profile = ExecutionProfile.parse(candidate.profile)
      expect(profile.verification.state).toBe('candidate')
      expect(new Set(Object.values(profile.provenance))).toEqual(new Set(['apis-guru']))
    }
  })
})
