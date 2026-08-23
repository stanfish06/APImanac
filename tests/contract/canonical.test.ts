import { readFileSync } from 'node:fs'
import { describe, expect, test } from 'bun:test'
import {
  CanonicalizationError,
  authorityFingerprint,
  canonicalHash,
  canonicalize,
  contractHash,
} from '../../src/catalog/canonical'
import { ExecutionProfile } from '../../src/schema/execution'
import { baseProfileInput, parseProfile } from '../helpers/profile'
import { fixturePath, loadFixture } from '../helpers/yaml'

interface CanonicalFixture {
  input: unknown
  canonical: string
}

const FIXTURES = ['key-order', 'nested', 'non-bmp', 'combining-marks', 'escapes']

describe('RFC 8785 canonicalization', () => {
  test.each(FIXTURES)('the %s fixture serializes to its committed canonical form', (name) => {
    const fixture = JSON.parse(
      readFileSync(fixturePath('canonical', `${name}.json`), 'utf8'),
    ) as CanonicalFixture
    expect(canonicalize(fixture.input)).toBe(fixture.canonical)
  })

  test('the canonical form is byte-stable for non-BMP text', () => {
    const first = Buffer.from(canonicalize({ e: '\u{1F600}' }), 'utf8')
    const second = Buffer.from(canonicalize({ e: '\u{1F600}' }), 'utf8')
    expect(first.equals(second)).toBe(true)
    expect(first.toString('hex')).toBe('7b2265223a22f09f9880227d')
  })

  test('precomposed and decomposed forms stay distinct', () => {
    expect(canonicalHash({ v: 'é' })).not.toBe(canonicalHash({ v: 'é' }))
  })

  test('a float in the projection is rejected rather than hashed', () => {
    expect(() => canonicalize({ ttl: 1.5 })).toThrow(CanonicalizationError)
    expect(() => canonicalize({ ttl: 1.5 })).toThrow('only integers')
  })

  test('a null in the projection is rejected rather than hashed', () => {
    expect(() => canonicalize({ value: null })).toThrow(CanonicalizationError)
    expect(() => canonicalize({ value: null })).toThrow('null is not representable')
  })

  test('negative zero and non-finite numbers are rejected', () => {
    expect(() => canonicalize({ n: -0 })).toThrow(CanonicalizationError)
    expect(() => canonicalize({ n: Number.POSITIVE_INFINITY })).toThrow(CanonicalizationError)
    expect(() => canonicalize({ n: Number.NaN })).toThrow(CanonicalizationError)
  })

  test('an unpaired surrogate is rejected', () => {
    expect(() => canonicalize({ s: '\ud800' })).toThrow('unpaired surrogate')
  })

  test('the error names the field path', () => {
    try {
      canonicalize({ outer: { inner: [1, null] } })
      throw new Error('expected a rejection')
    } catch (error) {
      expect((error as CanonicalizationError).path).toBe('.outer.inner[1]')
    }
  })
})

describe('formatting equivalence', () => {
  test('two YAML files differing only in formatting canonicalize identically', () => {
    const a = ExecutionProfile.parse(loadFixture('canonical', 'formatting', 'a.yaml'))
    const b = ExecutionProfile.parse(loadFixture('canonical', 'formatting', 'b.yaml'))
    expect(contractHash(a)).toBe(contractHash(b))
    expect(authorityFingerprint(a)).toBe(authorityFingerprint(b))
  })
})

describe('contract hash', () => {
  test('carries the v1:sha256 tag', () => {
    expect(contractHash(parseProfile())).toMatch(/^v1:sha256:[0-9a-f]{64}$/)
  })

  test('a verification-block-only change leaves it unchanged', () => {
    const candidate = parseProfile()
    const verified = ExecutionProfile.parse(
      baseProfileInput({
        verification: {
          state: 'verified',
          verified_at: '2026-01-01T00:00:00Z',
          evidence: {
            contract_hash: contractHash(candidate),
            method: 'GET',
            path: '/works',
            status: 200,
            response_hash: `v1:sha256:${'0'.repeat(64)}`,
            timestamp: '2026-01-01T00:00:00Z',
            tool_version: '0.0.0',
          },
        },
      }),
    )
    expect(contractHash(verified)).toBe(contractHash(candidate))
  })

  test.each([
    ['origins', { origins: ['https://api2.example.com'] }],
    [
      'a permission rule',
      { permissions: [{ method: 'GET', path: '/works/**', decision: 'confirm' }] },
    ],
    ['network scope', { network_scope: 'private' }],
    ['a response bound', { response: { inline_max_bytes: 1024 } }],
    ['the base path', { base_path: '/v1' }],
    ['the cache ttl', { cache: { ttl_seconds: 60 } }],
  ])('changing %s changes it', (_label, overrides) => {
    expect(contractHash(parseProfile(overrides))).not.toBe(contractHash(parseProfile()))
  })
})

describe('authority fingerprint', () => {
  const bearer = {
    type: 'bearer',
    credential_id: 'example',
    components: [{ name: 'token' }],
    placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
  }

  test('carries the v1:sha256 tag and no credential material', () => {
    const fingerprint = authorityFingerprint(parseProfile({ auth: bearer }))
    expect(fingerprint).toMatch(/^v1:sha256:[0-9a-f]{64}$/)
  })

  test.each([
    [
      'moving the credential from a header to a query parameter',
      {
        auth: {
          ...bearer,
          type: 'query_key',
          components: [{ name: 'key' }],
          placements: [{ kind: 'query', parameter: 'api_key', template: '{key}' }],
        },
      },
    ],
    [
      'adding a required component',
      { auth: { ...bearer, components: [{ name: 'token' }, { name: 'account' }] } },
    ],
    [
      'widening the origins',
      { auth: bearer, origins: ['https://api.example.com', 'https://b.example.com'] },
    ],
    ['changing the network scope', { auth: bearer, network_scope: 'private' }],
    ['changing the base path', { auth: bearer, base_path: '/v2' }],
    [
      'adding a credential-forwarding pair',
      {
        auth: bearer,
        origins: ['https://api.example.com', 'https://b.example.com'],
        redirects: {
          forward_credentials: [{ from: 'https://api.example.com', to: 'https://b.example.com' }],
        },
      },
    ],
  ])('changes when %s', (_label, overrides) => {
    const base = parseProfile({ auth: bearer })
    expect(authorityFingerprint(parseProfile(overrides))).not.toBe(authorityFingerprint(base))
  })

  test.each([
    ['the description', { description: 'a different description' }],
    ['the cache ttl', { cache: { ttl_seconds: 60 } }],
    ['a permission rule', { permissions: [{ method: 'GET', path: '/x/**', decision: 'deny' }] }],
    ['the health probe', { health_probe: { path: '/ping' } }],
  ])('is unchanged when %s changes', (_label, overrides) => {
    const base = parseProfile({ auth: bearer })
    expect(authorityFingerprint(parseProfile({ auth: bearer, ...overrides }))).toBe(
      authorityFingerprint(base),
    )
  })

  test('widening origins changes the fingerprint but a formatting reorder does not', () => {
    const one = parseProfile({
      auth: bearer,
      origins: ['https://b.example.com', 'https://api.example.com'],
    })
    const two = parseProfile({
      auth: bearer,
      origins: ['https://api.example.com', 'https://b.example.com'],
    })
    expect(authorityFingerprint(one)).toBe(authorityFingerprint(two))
  })
})
