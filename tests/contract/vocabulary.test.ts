import { describe, expect, test } from 'bun:test'
import { MetadataRecord } from '../../src/schema/metadata'
import { ExecutionProfile } from '../../src/schema/execution'
import {
  AUTH_TYPES,
  CREDENTIAL_READINESS,
  CURATION_STATES,
  DESCRIBABLE_AUTH_TYPES,
  EXECUTABLE_AUTH_TYPES,
  HEALTH_STATES,
  LIFECYCLE_STATES,
  NETWORK_SCOPES,
  PERMISSION_DECISIONS,
  RESPONSE_MODES,
  VERIFICATION_STATES,
  isExecutableAuthType,
} from '../../src/schema/vocab'
import { baseProfileInput } from '../helpers/profile'

describe('closed vocabularies', () => {
  test('hold exactly the declared values', () => {
    expect([...CURATION_STATES]).toEqual(['imported', 'curated'])
    expect([...LIFECYCLE_STATES]).toEqual(['active', 'deprecated', 'gone', 'merged'])
    expect([...VERIFICATION_STATES]).toEqual(['candidate', 'verified'])
    expect([...NETWORK_SCOPES]).toEqual(['public', 'private'])
    expect([...PERMISSION_DECISIONS]).toEqual(['auto', 'confirm', 'deny'])
    expect([...RESPONSE_MODES]).toEqual(['inline', 'file'])
    expect([...HEALTH_STATES]).toEqual([
      'unknown',
      'healthy',
      'auth_required',
      'rate_limited',
      'degraded',
      'unreachable',
    ])
    expect([...CREDENTIAL_READINESS]).toEqual([
      'not_required',
      'ready',
      'no_grant',
      'missing_component',
      'fingerprint_mismatch',
      'unsupported_auth',
      'ambiguous_account',
    ])
    expect([...EXECUTABLE_AUTH_TYPES]).toEqual([
      'none',
      'bearer',
      'header_key',
      'query_key',
      'basic',
    ])
    expect([...DESCRIBABLE_AUTH_TYPES]).toEqual(['oauth2', 'signed', 'custom'])
    expect([...AUTH_TYPES]).toEqual([...EXECUTABLE_AUTH_TYPES, ...DESCRIBABLE_AUTH_TYPES])
  })

  test('describable auth types are not executable', () => {
    for (const type of DESCRIBABLE_AUTH_TYPES) expect(isExecutableAuthType(type)).toBe(false)
    for (const type of EXECUTABLE_AUTH_TYPES) expect(isExecutableAuthType(type)).toBe(true)
  })

  test('an out-of-vocabulary lifecycle is rejected at parse time', () => {
    const result = MetadataRecord.safeParse({
      id: 'example',
      name: 'Example',
      lifecycle: 'retired',
    })
    expect(result.success).toBe(false)
    if (!result.success) {
      const issue = result.error.issues.find((i) => i.path.join('.') === 'lifecycle')
      expect(issue).toBeDefined()
      expect(JSON.stringify(issue)).toContain('deprecated')
    }
  })

  test('an out-of-vocabulary permission decision is rejected at parse time', () => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({ permissions: [{ method: 'GET', path: '/x', decision: 'allow' }] }),
    )
    expect(result.success).toBe(false)
  })

  test('an out-of-vocabulary network scope is rejected at parse time', () => {
    expect(
      ExecutionProfile.safeParse(baseProfileInput({ network_scope: 'internal' })).success,
    ).toBe(false)
  })

  test('an out-of-vocabulary auth type is rejected at parse time', () => {
    expect(ExecutionProfile.safeParse(baseProfileInput({ auth: { type: 'mtls' } })).success).toBe(
      false,
    )
  })
})

describe('every surface imports the same declarations', () => {
  test('no module outside schema/vocab.ts re-declares a vocabulary set', async () => {
    const root = Bun.fileURLToPath(new URL('../../src', import.meta.url))
    const glob = new Bun.Glob('**/*.ts')
    const restatements = [
      "'auth_required', 'rate_limited'",
      "'imported', 'curated'",
      "'active', 'deprecated', 'gone', 'merged'",
      "'candidate', 'verified'",
      "'auto', 'confirm', 'deny'",
    ]
    let checked = 0
    for await (const relative of glob.scan(root)) {
      if (relative === 'schema/vocab.ts') continue
      const text = await Bun.file(`${root}/${relative}`).text()
      for (const restatement of restatements) {
        expect(`${relative}: ${text.includes(restatement)}`).toBe(`${relative}: false`)
      }
      checked += 1
    }
    expect(checked).toBeGreaterThan(0)
  })
})
