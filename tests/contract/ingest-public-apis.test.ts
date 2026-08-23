import { describe, expect, test } from 'bun:test'
import { buildLedger, type SourcePin } from '../../src/ingest/adapter'
import { publicApisAdapter, runPublicApis } from '../../src/ingest/public-apis'
import { MetadataRecord } from '../../src/schema/metadata'
import { OutcomeLedger } from '../../src/schema/report'
import { loadFixture } from '../helpers/yaml'

const pin = (() => {
  const value = loadFixture('sources', 'public-apis', 'pin.yaml') as Record<string, string>
  return {
    revision: value.revision ?? '',
    contentHash: value.content_hash ?? '',
    retrievedAt: value.retrieved_at ?? '',
  } satisfies SourcePin
})()

function run() {
  return runPublicApis(loadFixture('sources', 'public-apis', 'entries.json'), pin)
}

function records() {
  return new Map(run().metadata.map((c) => [c.sourceEntryId, MetadataRecord.parse(c.record)]))
}

function rejections() {
  return new Map(run().rejections.map((r) => [r.sourceEntryId, r]))
}

describe('public-apis adapter', () => {
  test('the import produces zero execution profiles', () => {
    expect(run().execution).toEqual([])
    expect(publicApisAdapter.sourceId).toBe('public-apis')
  })

  test('a documentation link is recorded as documentation and yields no execution origin', () => {
    const record = records().get('Cat Facts')
    expect(record?.documentation).toBe('https://catfact.ninja/')
    expect(record?.homepage).toBeUndefined()
    const serialized = JSON.stringify(run())
    expect(serialized).not.toContain('origins')
    expect(serialized).not.toContain('base_path')
  })

  test('a coarse apiKey label becomes a tag and creates no credential placement', () => {
    const record = records().get('Airtable')
    expect(record?.tags).toEqual(['auth:apikey'])
    expect(JSON.stringify(run())).not.toContain('placements')
    expect(JSON.stringify(run())).not.toContain('credential_id')
  })

  test('an entry with no auth label still carries a descriptive tag', () => {
    expect(records().get('Cat Facts')?.tags).toEqual(['auth:none'])
  })

  test('the raw name is kept as an alias when it differs from the slug', () => {
    const record = records().get('api.data.gov')
    expect(record?.id).toBe('api-data-gov')
    expect(record?.aliases).toContain('api.data.gov')
  })

  test('two entries that slugify to one id import once and alias the second', () => {
    const result = run()
    const ids = result.metadata.map((c) => MetadataRecord.parse(c.record).id)
    expect(ids.filter((id) => id === 'open-library').length).toBe(1)
    expect(result.aliased).toContainEqual(
      expect.objectContaining({ sourceEntryId: 'Open.Library', apiId: 'open-library' }),
    )
    expect(records().get('Open Library')?.aliases).toContain('open.library')
  })

  test('each unusable entry cites its declared reason code', () => {
    const rejected = rejections()
    expect(rejected.get('No Link API')?.reasonCode).toBe('missing_link')
    expect(rejected.get('FTP Directory')?.reasonCode).toBe('invalid_link')
    expect(rejected.get('Uncategorized Service')?.reasonCode).toBe('unusable_category')
    const derived = [...rejected.values()].filter((r) => r.sourceEntryId.startsWith('public-apis:'))
    expect(derived.map((r) => r.reasonCode).sort()).toEqual(['missing_name', 'schema_mismatch'])
    for (const rejection of rejected.values()) {
      expect(publicApisAdapter.reasons.codes).toContain(rejection.reasonCode)
    }
  })

  test('every metadata candidate parses as a metadata record and names its source', () => {
    for (const candidate of run().metadata) {
      const record = MetadataRecord.parse(candidate.record)
      expect(record.sources).toEqual(['public-apis'])
      expect(record.curation).toBe('imported')
      expect(record.profiles).toEqual([])
      expect(record.provenance.documentation?.source).toBe('public-apis')
    }
  })

  test('the ledger accounts for every fixture entry', () => {
    const ledger = OutcomeLedger.parse(buildLedger(run()))
    expect(ledger.source_id).toBe('public-apis')
    const counts = { imported: 0, aliased: 0, rejected: 0 }
    for (const entry of ledger.entries) counts[entry.outcome] += 1
    expect(counts).toEqual({ imported: 5, aliased: 1, rejected: 5 })
  })
})
