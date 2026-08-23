import { describe, expect, test } from 'bun:test'
import { ExecutionProfile } from '../../src/schema/execution'
import { GrantsFile } from '../../src/schema/grant'
import { RootManifest, SUPPORTED_SCHEMA_VERSION } from '../../src/schema/manifest'
import { MetadataRecord } from '../../src/schema/metadata'
import { OutcomeLedger } from '../../src/schema/report'
import { baseProfileInput } from '../helpers/profile'
import { loadFixture } from '../helpers/yaml'

describe('root manifest', () => {
  test('the valid fixture parses and owns the schema version', () => {
    const manifest = RootManifest.parse(loadFixture('manifest', 'valid.yaml'))
    expect(manifest.schema_version).toBe(SUPPORTED_SCHEMA_VERSION)
    expect(manifest.sources[0]?.id).toBe('public-apis')
  })

  test('an unsupported schema version parses but does not equal the supported one', () => {
    const manifest = RootManifest.parse(loadFixture('manifest', 'unsupported-version.yaml'))
    expect(manifest.schema_version).not.toBe(SUPPORTED_SCHEMA_VERSION)
  })

  test('an unknown top-level key is rejected', () => {
    const result = RootManifest.safeParse(loadFixture('manifest', 'unknown-key.yaml'))
    expect(result.success).toBe(false)
  })

  test('a duplicate source id is rejected', () => {
    const result = RootManifest.safeParse(loadFixture('manifest', 'duplicate-source.yaml'))
    expect(result.success).toBe(false)
    if (!result.success) expect(result.error.issues[0]?.message).toContain('duplicate source id')
  })

  test('a vocabulary that is not the closed set is rejected', () => {
    const result = RootManifest.safeParse(loadFixture('manifest', 'bad-vocabulary.yaml'))
    expect(result.success).toBe(false)
  })
})

describe('metadata records', () => {
  test('every lifecycle value has a fixture that parses', () => {
    for (const lifecycle of ['active', 'deprecated', 'gone', 'merged'] as const) {
      const record = MetadataRecord.parse(loadFixture('metadata', `lifecycle-${lifecycle}.yaml`))
      expect(record.lifecycle).toBe(lifecycle)
    }
  })

  test('a record declaring its own schema version is rejected', () => {
    const result = MetadataRecord.safeParse(loadFixture('metadata', 'declares-schema-version.yaml'))
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues.some((i) => i.path.includes('schema_version'))).toBe(true)
    }
  })

  test('a non-conforming canonical id is rejected naming the id field', () => {
    const result = MetadataRecord.safeParse(loadFixture('metadata', 'bad-id.yaml'))
    expect(result.success).toBe(false)
    if (!result.success) expect(result.error.issues[0]?.path).toEqual(['id'])
  })

  test('a merged record without a target is rejected', () => {
    const result = MetadataRecord.safeParse(loadFixture('metadata', 'merged-without-target.yaml'))
    expect(result.success).toBe(false)
    if (!result.success) expect(result.error.issues[0]?.path).toEqual(['merged_into'])
  })

  test('a record aliasing its own canonical id is rejected', () => {
    const result = MetadataRecord.safeParse({ id: 'x', name: 'X', aliases: ['x'] })
    expect(result.success).toBe(false)
  })

  test('a record with no execution profile is valid and discovery-only', () => {
    const record = MetadataRecord.parse({ id: 'x', name: 'X' })
    expect(record.profiles).toEqual([])
  })
})

describe('execution profiles', () => {
  test('a minimal no-auth profile parses with defaults applied', () => {
    const profile = ExecutionProfile.parse(baseProfileInput())
    expect(profile.network_scope).toBe('public')
    expect(profile.redirects.max).toBe(5)
    expect(profile.cache.enabled).toBe(false)
    expect(profile.verification.state).toBe('candidate')
  })

  test.each([
    ['wildcard', 'https://*.example.com'],
    ['path', 'https://api.example.com/v1'],
    ['trailing slash path', 'https://api.example.com/'],
    ['userinfo', 'https://user:pw@api.example.com'],
    ['query', 'https://api.example.com?a=1'],
    ['fragment', 'https://api.example.com#f'],
    ['uppercase host', 'https://API.example.com'],
    ['no scheme', 'api.example.com'],
    ['unsupported scheme', 'ftp://api.example.com'],
  ])('an origin with a %s is rejected', (_label, origin) => {
    const result = ExecutionProfile.safeParse(baseProfileInput({ origins: [origin] }))
    expect(result.success).toBe(false)
    if (!result.success) expect(JSON.stringify(result.error.issues)).toContain(origin)
  })

  test('an exact origin with a non-default port is accepted', () => {
    const profile = ExecutionProfile.parse(
      baseProfileInput({ origins: ['https://api.example.com:8443'] }),
    )
    expect(profile.origins).toEqual(['https://api.example.com:8443'])
  })

  test('a base path with traversal is rejected', () => {
    expect(
      ExecutionProfile.safeParse(baseProfileInput({ base_path: '/v1/../admin' })).success,
    ).toBe(false)
  })

  test('credential forwarding must name this profile’s own origins', () => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({
        redirects: {
          forward_credentials: [
            { from: 'https://api.example.com', to: 'https://other.example.com' },
          ],
        },
      }),
    )
    expect(result.success).toBe(false)
  })

  test('basic auth records two separate components', () => {
    const profile = ExecutionProfile.parse(
      baseProfileInput({
        auth: {
          type: 'basic',
          credential_id: 'example-basic',
          components: [{ name: 'username' }, { name: 'password' }],
          placements: [{ kind: 'basic', username: 'username', password: 'password' }],
        },
      }),
    )
    expect(profile.auth.components.map((c) => c.name)).toEqual(['username', 'password'])
  })

  test('an authenticated profile without a credential id is rejected', () => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({
        auth: {
          type: 'bearer',
          components: [{ name: 'token' }],
          placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
        },
      }),
    )
    expect(result.success).toBe(false)
  })

  test('`verified` without evidence is rejected', () => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({ verification: { state: 'verified' } }),
    )
    expect(result.success).toBe(false)
  })
})

describe('auth template placeholders', () => {
  test('an undeclared placeholder is rejected', () => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({
        auth: {
          type: 'bearer',
          credential_id: 'example',
          components: [{ name: 'token' }],
          placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {secret}' }],
        },
      }),
    )
    expect(result.success).toBe(false)
    if (!result.success) expect(JSON.stringify(result.error.issues)).toContain('{secret}')
  })

  test('an arbitrary interpolation expression is rejected', () => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({
        auth: {
          type: 'bearer',
          credential_id: 'example',
          components: [{ name: 'token' }],
          placements: [
            { kind: 'header', header: 'Authorization', template: 'Bearer {token.slice(0,4)}' },
          ],
        },
      }),
    )
    expect(result.success).toBe(false)
  })

  test('a basic placement naming an undeclared component is rejected', () => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({
        auth: {
          type: 'basic',
          credential_id: 'example',
          components: [{ name: 'username' }, { name: 'password' }],
          placements: [{ kind: 'basic', username: 'username', password: 'passphrase' }],
        },
      }),
    )
    expect(result.success).toBe(false)
  })
})

describe('grants', () => {
  const grant = {
    credential_id: 'example-key',
    api_id: 'example',
    profile_id: 'public',
    origins: ['https://api.example.com'],
    authority_fingerprint: `v1:sha256:${'a'.repeat(64)}`,
    accounts: [
      { name: 'default', default: true, components: { key: { provider: 'env', variable: 'X' } } },
    ],
  }

  test('a complete grant parses', () => {
    const parsed = GrantsFile.parse({ grants: [grant] })
    expect(parsed.grants[0]?.accounts[0]?.name).toBe('default')
  })

  test('a grant with no component binding is rejected', () => {
    const result = GrantsFile.safeParse({
      grants: [{ ...grant, accounts: [{ name: 'default', components: {} }] }],
    })
    expect(result.success).toBe(false)
    if (!result.success) expect(JSON.stringify(result.error.issues)).toContain('binds no component')
  })

  test('two default accounts are rejected', () => {
    const result = GrantsFile.safeParse({
      grants: [
        {
          ...grant,
          accounts: [
            { name: 'a', default: true, components: { key: { provider: 'env', variable: 'A' } } },
            { name: 'b', default: true, components: { key: { provider: 'env', variable: 'B' } } },
          ],
        },
      ],
    })
    expect(result.success).toBe(false)
  })

  test('an untagged fingerprint is rejected', () => {
    const result = GrantsFile.safeParse({
      grants: [{ ...grant, authority_fingerprint: 'a'.repeat(64) }],
    })
    expect(result.success).toBe(false)
  })
})

describe('outcome ledgers', () => {
  const hash = `v1:sha256:${'b'.repeat(64)}`

  test('a ledger citing an undeclared reason code is rejected', () => {
    const result = OutcomeLedger.safeParse({
      source_id: 'public-apis',
      reason_codes_version: 1,
      entries: [
        { source_entry_id: 'e1', content_hash: hash, outcome: 'rejected', reason_code: 'because' },
      ],
    })
    expect(result.success).toBe(false)
    if (!result.success) expect(JSON.stringify(result.error.issues)).toContain('because')
  })

  test('a ledger for an unknown source is rejected', () => {
    const result = OutcomeLedger.safeParse({ source_id: 'unknown', reason_codes_version: 1 })
    expect(result.success).toBe(false)
  })

  test('two outcomes for one entry are rejected', () => {
    const result = OutcomeLedger.safeParse({
      source_id: 'public-apis',
      reason_codes_version: 1,
      entries: [
        { source_entry_id: 'e1', content_hash: hash, outcome: 'imported', api_id: 'a' },
        { source_entry_id: 'e1', content_hash: hash, outcome: 'aliased', api_id: 'a' },
      ],
    })
    expect(result.success).toBe(false)
    if (!result.success) expect(JSON.stringify(result.error.issues)).toContain('two outcomes')
  })

  test('a mismatched reason vocabulary version is rejected', () => {
    const result = OutcomeLedger.safeParse({ source_id: 'nango', reason_codes_version: 99 })
    expect(result.success).toBe(false)
  })
})
