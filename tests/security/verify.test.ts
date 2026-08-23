import { readFileSync, writeFileSync } from 'node:fs'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { parse, stringify } from 'yaml'
import { GrantStore } from '../../src/auth/grants'
import { injectedProvider } from '../../src/auth/providers'
import { profilePath } from '../../src/catalog/load'
import { callApi } from '../../src/execute/call'
import { ApprovalTokens } from '../../src/execute/confirm'
import { HealthStore } from '../../src/execute/health'
import { verifyProfile } from '../../src/execute/verify'
import { evaluateEligibility } from '../../src/policy/eligibility'
import { MOCK_SECRET } from '../fixtures/http/mock-server'
import {
  alwaysAccept,
  alwaysDecline,
  executionFixture,
  fingerprintOf,
  readProfile,
  type ExecutionFixture,
} from '../helpers/execution'

let fixture: ExecutionFixture

beforeAll(async () => {
  fixture = await executionFixture()
})

afterAll(() => fixture.dispose())

function noGrants() {
  return GrantStore.load({ path: fixture.grantsPath, provider: injectedProvider({}) })
}

function grantFor(profileId: string, values: Record<string, string>) {
  const profile = readProfile(fixture.repo, profileId)
  writeFileSync(
    fixture.grantsPath,
    stringify({
      version: 1,
      grants: [
        {
          credential_id: profile.auth.credential_id,
          api_id: 'mock',
          profile_id: profileId,
          origins: profile.origins,
          authority_fingerprint: fingerprintOf(fixture.repo, profileId),
          accounts: [
            {
              name: 'primary',
              components: Object.fromEntries(
                Object.keys(values).map((name) => [name, { provider: 'env', variable: 'X' }]),
              ),
            },
          ],
        },
      ],
    }),
    { mode: 0o600 },
  )
  return GrantStore.load({ path: fixture.grantsPath, provider: injectedProvider(values) })
}

async function verify(profileId: string, overrides: Record<string, unknown> = {}) {
  const health = HealthStore.open(fixture.healthPath)
  try {
    return await verifyProfile(
      { root: fixture.reopen(), api: 'mock', profile: profileId },
      { grants: noGrants(), channel: alwaysAccept(), health, ...overrides },
    )
  } finally {
    health.close()
  }
}

describe('verify runs every check before the probe', () => {
  test('a missing profile file is a typed not-found', async () => {
    const outcome = await verify('absent')
    expect(outcome.kind).toBe('not_found')
  })

  test('an invalid candidate sends no probe', async () => {
    const file = profilePath('mock', 'brokenschema')
    fixture.repo.write(file, 'profile_id: brokenschema\napi_id: mock\norigins: []\n')
    const before = fixture.mock.requests.length
    const outcome = await verify('brokenschema')
    expect(outcome.kind).toBe('invalid')
    expect(fixture.mock.requests.length).toBe(before)
    fixture.repo.remove(file)
  })

  test('a candidate declaring an unsupported auth type sends no probe', async () => {
    fixture.writeProfile(
      'oauthcandidate',
      {
        auth: {
          type: 'oauth2',
          credential_id: 'mock-oauth',
          components: [{ name: 'access_token' }],
        },
      },
      false,
    )
    const before = fixture.mock.requests.length
    const outcome = await verify('oauthcandidate')
    expect(outcome.kind).toBe('unsupported_auth')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a candidate without a health probe has nothing to verify against', async () => {
    fixture.writeProfile('noprobe', { health_probe: undefined }, false)
    const outcome = await verify('noprobe')
    expect(outcome.kind).toBe('no_probe')
  })

  test('a probe outside the declared base path fails schema validation', async () => {
    fixture.writeProfile('badprobe', { base_path: '/ok' }, false)
    const file = fixture.repo.path(profilePath('mock', 'badprobe'))
    const document = parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    document.health_probe = { method: 'GET', path: '/echo', expect_status: 200 }
    writeFileSync(file, stringify(document))
    const before = fixture.mock.requests.length
    const outcome = await verify('badprobe')
    expect(outcome.kind).toBe('invalid')
    expect(outcome.message).toContain('outside the profile base path')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a probe path the URL layer rejects sends no probe', async () => {
    fixture.writeProfile('encodedprobe', {}, false)
    // A slash-prefixed path the schema accepts but percent normalization rejects.
    const file = fixture.repo.path(profilePath('mock', 'encodedprobe'))
    const document = parse(readFileSync(file, 'utf8')) as Record<string, unknown>
    document.health_probe = { method: 'GET', path: '/a%2Fb', expect_status: 200 }
    writeFileSync(file, stringify(document))
    const before = fixture.mock.requests.length
    const outcome = await verify('encodedprobe')
    expect(outcome.kind).toBe('invalid')
    expect(outcome.message).toContain('encoded_path_separator')
    expect(fixture.mock.requests.length).toBe(before)
  })
})

describe('verification always confirms interactively', () => {
  test('a candidate marking its probe auto still prompts', async () => {
    fixture.writeProfile(
      'autoprobe',
      { permissions: [{ method: 'GET', path: '/**', decision: 'auto' }] },
      false,
    )
    let asked = false
    const outcome = await verify('autoprobe', {
      channel: {
        label: 'test' as const,
        confirm: async () => {
          asked = true
          return true
        },
      },
    })
    expect(asked).toBe(true)
    expect(outcome.kind).toBe('verified')
  })

  test('non-interactive verification refuses without sending the probe', async () => {
    fixture.writeProfile('nointeract', {}, false)
    const before = fixture.mock.requests.length
    const outcome = await verify('nointeract', { channel: undefined })
    expect(outcome.kind).toBe('no_terminal')
    expect(outcome.message).toContain('interactive confirmation')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a declined confirmation sends no probe', async () => {
    fixture.writeProfile('declined', {}, false)
    const before = fixture.mock.requests.length
    const outcome = await verify('declined', { channel: alwaysDecline() })
    expect(outcome.kind).toBe('declined')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('the preview shows the exact origin and path', async () => {
    fixture.writeProfile('previewed', {}, false)
    let summary = ''
    await verify('previewed', {
      channel: {
        label: 'test' as const,
        confirm: async (preview: { summary: string }) => {
          summary = preview.summary
          return false
        },
      },
    })
    expect(summary).toContain(fixture.mock.origin)
    expect(summary).toContain('/ok')
  })
})

describe('checks read the worktree candidate, not the committed snapshot', () => {
  test('an uncommitted candidate with a matching activated grant can be probed', async () => {
    fixture.writeProfile(
      'bootstrap',
      {
        auth: {
          type: 'bearer',
          credential_id: 'mock-token',
          components: [{ name: 'token' }],
          placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
        },
        health_probe: { method: 'GET', path: '/auth', expect_status: 200 },
      },
      false,
    )
    // The profile has never been committed; the grant binds the worktree candidate.
    expect(evaluateEligibility(fixture.reopen(), 'mock', 'bootstrap').eligible).toBe(false)
    const grants = grantFor('bootstrap', { token: MOCK_SECRET })
    const outcome = await verify('bootstrap', { grants })
    expect(outcome.kind).toBe('verified')
    expect(outcome.authority_fingerprint).toBe(fingerprintOf(fixture.repo, 'bootstrap'))
  })

  test('an authenticated probe with no grant refuses without resolving a credential', async () => {
    fixture.writeProfile(
      'ungranted',
      {
        auth: {
          type: 'bearer',
          credential_id: 'mock-token',
          components: [{ name: 'token' }],
          placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
        },
        health_probe: { method: 'GET', path: '/auth', expect_status: 200 },
      },
      false,
    )
    writeFileSync(fixture.grantsPath, stringify({ version: 1, grants: [] }), { mode: 0o600 })
    const before = fixture.mock.requests.length
    const outcome = await verify('ungranted')
    expect(outcome.kind).toBe('missing_grant')
    expect(outcome.message).toContain('Bind a grant to')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a grant bound to a stale fingerprint refuses after the candidate changes', async () => {
    fixture.writeProfile(
      'rebound',
      {
        auth: {
          type: 'bearer',
          credential_id: 'mock-token',
          components: [{ name: 'token' }],
          placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
        },
        health_probe: { method: 'GET', path: '/auth', expect_status: 200 },
      },
      false,
    )
    const grants = grantFor('rebound', { token: MOCK_SECRET })
    // Widening the origins changes the fingerprint the grant was activated against.
    fixture.writeProfile(
      'rebound',
      {
        origins: [fixture.mock.origin, fixture.peer.origin],
        auth: {
          type: 'bearer',
          credential_id: 'mock-token',
          components: [{ name: 'token' }],
          placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
        },
        health_probe: { method: 'GET', path: '/auth', expect_status: 200 },
      },
      false,
    )
    const before = fixture.mock.requests.length
    const outcome = await verify('rebound', { grants })
    expect(outcome.kind).toBe('missing_grant')
    expect(fixture.mock.requests.length).toBe(before)
  })
})

describe('evidence is written as an uncommitted change', () => {
  test('evidence records hashes and a sanitized summary with no body or credential', async () => {
    fixture.writeProfile('evidenced', {}, false)
    const outcome = await verify('evidenced')
    expect(outcome.kind).toBe('verified')
    const document = parse(
      readFileSync(fixture.repo.path(profilePath('mock', 'evidenced')), 'utf8'),
    ) as { verification: { state: string; evidence: Record<string, unknown> } }
    expect(document.verification.state).toBe('verified')
    expect(Object.keys(document.verification.evidence).sort()).toEqual([
      'contract_hash',
      'method',
      'path',
      'response_hash',
      'status',
      'timestamp',
      'tool_version',
    ])
    const serialized = JSON.stringify(document)
    expect(serialized).not.toContain('"ok":true')
    expect(serialized).not.toContain(MOCK_SECRET)
  })

  test('the profile stays ineligible until the change is committed', async () => {
    fixture.writeProfile('pendingreview', {}, false)
    fixture.repo.commit('commit the candidate')
    expect((await verify('pendingreview')).kind).toBe('verified')
    // Evidence is written but not committed, so the file is dirty.
    const still = evaluateEligibility(fixture.reopen(), 'mock', 'pendingreview')
    expect(still.eligible).toBe(false)
    if (!still.eligible) expect(still.code).toBe('modified')
    fixture.repo.commit('reviewer commits the evidence')
    expect(evaluateEligibility(fixture.reopen(), 'mock', 'pendingreview').eligible).toBe(true)
  })

  test('the Git index and refs are unchanged by verify', async () => {
    fixture.writeProfile('nostage', {}, false)
    fixture.repo.commit('commit the candidate')
    const headBefore = fixture.repo.git('rev-parse', 'HEAD').trim()
    const indexBefore = fixture.repo.git('diff', '--cached', '--name-only')
    await verify('nostage')
    expect(fixture.repo.git('rev-parse', 'HEAD').trim()).toBe(headBefore)
    expect(fixture.repo.git('diff', '--cached', '--name-only')).toBe(indexBefore)
    expect(fixture.repo.git('status', '--porcelain')).toContain('nostage.yaml')
  })

  test('a probe whose status differs from the declared one is not verified', async () => {
    fixture.writeProfile(
      'wrongstatus',
      { health_probe: { method: 'GET', path: '/status/500', expect_status: 200 } },
      false,
    )
    const outcome = await verify('wrongstatus')
    expect(outcome.kind).toBe('probe_failed')
    expect(outcome.status).toBe(500)
    const document = parse(
      readFileSync(fixture.repo.path(profilePath('mock', 'wrongstatus')), 'utf8'),
    ) as { verification: { state: string } }
    expect(document.verification.state).toBe('candidate')
  })

  test('a failing content predicate is not verified', async () => {
    fixture.writeProfile(
      'wrongbody',
      {
        health_probe: {
          method: 'GET',
          path: '/ok',
          expect_status: 200,
          expect_body_contains: 'absent-marker',
        },
      },
      false,
    )
    const outcome = await verify('wrongbody')
    expect(outcome.kind).toBe('probe_failed')
  })
})

describe('an ordinary call refuses a candidate before resolving a credential', () => {
  test('the refusal directs the caller to verify', async () => {
    fixture.writeProfile(
      'candidateauth',
      {
        auth: {
          type: 'bearer',
          credential_id: 'mock-token',
          components: [{ name: 'token' }],
          placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
        },
      },
      false,
    )
    fixture.repo.commit('commit the authenticated candidate')
    const health = HealthStore.open(fixture.healthPath)
    try {
      const outcome = await callApi(
        {
          root: fixture.reopen(),
          api: 'mock',
          profile: 'candidateauth',
          method: 'GET',
          path: '/ok',
        },
        {
          grants: grantFor('candidateauth', { token: MOCK_SECRET }),
          tokens: new ApprovalTokens('test'),
          health,
        },
      )
      expect(outcome.kind).toBe('ineligible')
      expect(outcome.message).toContain('apimanac verify')
    } finally {
      health.close()
    }
  })
})
