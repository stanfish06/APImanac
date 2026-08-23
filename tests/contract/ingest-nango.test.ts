import { describe, expect, test } from 'bun:test'
import { buildLedger, type SourcePin } from '../../src/ingest/adapter'
import { nangoAdapter, runNango } from '../../src/ingest/nango'
import { ExecutionProfile } from '../../src/schema/execution'
import { MetadataRecord } from '../../src/schema/metadata'
import { OutcomeLedger } from '../../src/schema/report'
import { loadFixture } from '../helpers/yaml'

const pin = (() => {
  const value = loadFixture('sources', 'nango', 'pin.yaml') as Record<string, string>
  return {
    revision: value.revision ?? '',
    contentHash: value.content_hash ?? '',
    retrievedAt: value.retrieved_at ?? '',
  } satisfies SourcePin
})()

function run(withScopes = true) {
  return runNango(
    loadFixture('sources', 'nango', 'providers.yaml'),
    pin,
    withScopes ? loadFixture('sources', 'nango', 'scopes.yaml') : undefined,
  )
}

function profiles() {
  return new Map(run().execution.map((c) => [c.sourceEntryId, ExecutionProfile.parse(c.profile)]))
}

function rejections() {
  return new Map(run().rejections.map((r) => [r.sourceEntryId, r]))
}

describe('nango adapter', () => {
  test('an alias resolves against its target and produces one record', () => {
    const result = run()
    const ids = result.metadata.map((c) => MetadataRecord.parse(c.record).id)
    expect(ids.filter((id) => id === 'airtable').length).toBe(1)
    expect(ids).not.toContain('airtable-pat')
    expect(result.aliased).toContainEqual(
      expect.objectContaining({ sourceEntryId: 'airtable-pat', apiId: 'airtable' }),
    )
    const airtable = result.metadata.find((c) => c.sourceEntryId === 'airtable')
    expect(MetadataRecord.parse(airtable?.record).aliases).toContain('airtable-pat')
    const ledger = OutcomeLedger.parse(buildLedger(result))
    expect(ledger.entries.find((e) => e.source_entry_id === 'airtable-pat')?.outcome).toBe(
      'aliased',
    )
  })

  test('a multi-component api key stays multi-component', () => {
    const profile = profiles().get('airtable')
    expect(profile?.auth.type).toBe('header_key')
    expect(profile?.auth.components.map((c) => c.name)).toEqual(['key', 'account_id'])
    expect(profile?.auth.placements).toEqual([
      { kind: 'header', header: 'X-Account', template: '{account_id}' },
      { kind: 'header', header: 'X-Api-Key', template: '{key}' },
    ])
  })

  test('proxy base url becomes an exact origin plus a base path', () => {
    const profile = profiles().get('airtable')
    expect(profile?.origins).toEqual(['https://api.airtable.com'])
    expect(profile?.base_path).toBe('/v0')
  })

  test('auth modes map onto the auth types v0 can execute', () => {
    const all = profiles()
    expect(all.get('linear')?.auth.type).toBe('bearer')
    expect(all.get('linear')?.auth.components.map((c) => c.name)).toEqual(['token'])
    expect(all.get('weatherapi')?.auth.type).toBe('query_key')
    expect(all.get('weatherapi')?.auth.placements).toEqual([
      { kind: 'query', parameter: 'key', template: '{key}' },
    ])
    expect(all.get('braintree')?.auth.type).toBe('basic')
    expect(all.get('braintree')?.auth.components.map((c) => c.name)).toEqual([
      'username',
      'password',
    ])
  })

  test('scopes from the scopes file land on the execution candidate', () => {
    expect(profiles().get('linear')?.auth.scopes).toEqual(['read', 'write', 'issues:create'])
    expect(profiles().get('airtable')?.auth.scopes).toEqual([
      'data.records:read',
      'schema.bases:read',
    ])
    const without = new Map(
      run(false).execution.map((c) => [c.sourceEntryId, ExecutionProfile.parse(c.profile)]),
    )
    expect(without.get('linear')?.auth.scopes).toEqual([])
  })

  test('an unsupported template construct rejects with a stable code and no partial candidate', () => {
    const result = run()
    expect(rejections().get('docusign')?.reasonCode).toBe('unsupported_template_construct')
    expect(result.metadata.some((c) => c.sourceEntryId === 'docusign')).toBe(false)
    expect(result.execution.some((c) => c.sourceEntryId === 'docusign')).toBe(false)
  })

  test('a connection-configured base url rejects rather than inventing an origin', () => {
    const result = run()
    expect(rejections().get('zendesk')?.reasonCode).toBe('connection_configuration_required')
    expect(result.execution.some((c) => c.sourceEntryId === 'zendesk')).toBe(false)
    expect(JSON.stringify(result.execution)).not.toContain('zendesk')
    expect(JSON.stringify(result.metadata)).not.toContain('zendesk')
  })

  test('the remaining rejections cite their declared codes', () => {
    const rejected = rejections()
    expect(rejected.get('github')?.reasonCode).toBe('unsupported_auth_mode')
    expect(rejected.get('notion')?.reasonCode).toBe('missing_base_url')
    expect(rejected.get('badbase')?.reasonCode).toBe('invalid_base_url')
    expect(rejected.get('mystery')?.reasonCode).toBe('missing_display_name')
    expect(rejected.get('broken')?.reasonCode).toBe('schema_mismatch')
    for (const rejection of rejected.values()) {
      expect(nangoAdapter.reasons.codes).toContain(rejection.reasonCode)
    }
  })

  test('every candidate parses and every profile is a candidate owned by nango', () => {
    const result = run()
    for (const candidate of result.metadata) {
      const record = MetadataRecord.parse(candidate.record)
      expect(record.sources).toEqual(['nango'])
      expect(record.profiles).toEqual(['nango'])
    }
    for (const candidate of result.execution) {
      const profile = ExecutionProfile.parse(candidate.profile)
      expect(profile.verification.state).toBe('candidate')
      expect(profile.verification.evidence).toBeUndefined()
      expect(new Set(Object.values(profile.provenance))).toEqual(new Set(['nango']))
    }
  })
})
