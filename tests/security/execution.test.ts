import { existsSync, writeFileSync } from 'node:fs'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { stringify } from 'yaml'
import { GrantStore } from '../../src/auth/grants'
import { injectedProvider } from '../../src/auth/providers'
import { profilePath } from '../../src/catalog/load'
import { callApi } from '../../src/execute/call'
import { ResponseCache } from '../../src/execute/cache'
import { ApprovalTokens } from '../../src/execute/confirm'
import { HealthStore } from '../../src/execute/health'
import { RESERVED_HEADERS, reservedHeadersFor } from '../../src/policy/reserved'
import { MOCK_BASIC_PASSWORD, MOCK_BASIC_USER, MOCK_SECRET } from '../fixtures/http/mock-server'
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
  fixture = await executionFixture({ slowMs: 400, largeBytes: 6 * 1024 * 1024 })
})

afterAll(() => fixture.dispose())

function grantsWith(values: Record<string, string>, profileId: string, accounts?: unknown[]) {
  const fingerprint = fingerprintOf(fixture.repo, profileId)
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
          authority_fingerprint: fingerprint,
          accounts: accounts ?? [
            {
              name: 'primary',
              components: Object.fromEntries(
                Object.keys(values).map((name) => [
                  name,
                  { provider: 'env', variable: `X_${name}` },
                ]),
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

async function call(overrides: Record<string, unknown>, services: Record<string, unknown> = {}) {
  const health = HealthStore.open(fixture.healthPath)
  try {
    return await callApi(
      {
        root: fixture.reopen(),
        api: 'mock',
        profile: 'public',
        method: 'GET',
        path: '/ok',
        ...overrides,
      } as Parameters<typeof callApi>[0],
      {
        grants: GrantStore.load({ path: fixture.grantsPath, provider: injectedProvider({}) }),
        tokens: new ApprovalTokens('test-session'),
        health,
        ...services,
      } as Parameters<typeof callApi>[1],
    )
  } finally {
    health.close()
  }
}

describe('URL and path refusals happen before any request', () => {
  test.each([
    ['a scheme-relative path', '//evil.example/x'],
    ['an absolute URL in the path field', 'https://evil.example/x'],
    ['a fragment', '/ok#frag'],
    ['an inline query', '/ok?a=1'],
    ['userinfo', '/user@host'],
    ['a backslash', '/a\\b'],
    ['an encoded path separator', '/a%2Fb'],
    ['encoded traversal', '/a/%2E%2E/b'],
    ['literal traversal', '/a/../b'],
  ])('%s is refused and reaches no endpoint', async (_label, path) => {
    const before = fixture.mock.requests.length
    const outcome = await call({ path })
    expect(outcome.kind).toBe('policy_failure')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a path outside the base path is refused', async () => {
    fixture.writeProfile('based', {
      base_path: '/ok',
      permissions: [{ method: 'GET', path: '/**', decision: 'auto' }],
    })
    fixture.repo.commit('add based profile')
    const before = fixture.mock.requests.length
    const outcome = await call({ profile: 'based', path: '/echo' })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('outside_base_path')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a same-host different-port origin is outside the allowed origin', async () => {
    const other = `http://127.0.0.1:${fixture.mock.port + 1}`
    const outcome = await call({ origin: other })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('origin_not_allowed')
  })
})

describe('egress scope', () => {
  test('a profile without a private scope cannot reach the loopback mock', async () => {
    const before = fixture.mock.requests.length
    const outcome = await call({ profile: 'unscoped' })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('loopback')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a profile declaring a private scope reaches it', async () => {
    const outcome = await call({ profile: 'public', path: '/ok' })
    expect(outcome.kind).toBe('success')
    expect(outcome.status).toBe(200)
  })
})

describe('redirects are revalidated', () => {
  test('a redirect leaving the profile origins is not followed at all', async () => {
    const outcome = await call({ path: '/redirect/external' })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('not one of this profile')
    expect(fixture.mock.requests.some((entry) => entry.path === '/ok')).toBe(true)
  })

  test('a redirect to a private address is not followed', async () => {
    const outcome = await call({ path: '/redirect/private' })
    expect(outcome.kind).toBe('policy_failure')
  })

  test('an over-long chain fails with a bounded-redirect error', async () => {
    const outcome = await call({ path: '/redirect/loop' })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('redirect chain')
  })

  test('a same-origin redirect completes', async () => {
    const outcome = await call({ path: '/redirect/same' })
    expect(outcome.kind).toBe('success')
    expect(outcome.status).toBe(200)
  })

  test('a credentialed cross-origin redirect without forwarding permission is refused', async () => {
    fixture.writeProfile('forwardless', {
      origins: [fixture.mock.origin, fixture.peer.origin],
      auth: {
        type: 'bearer',
        credential_id: 'mock-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      permissions: [{ method: 'GET', path: '/redirect/**', decision: 'auto' }],
    })
    fixture.repo.commit('add forwardless profile')
    const grants = grantsWith({ token: MOCK_SECRET }, 'forwardless')
    const outcome = await call({ profile: 'forwardless', path: '/redirect/peer' }, { grants })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('does not permit forwarding')
  })

  test('a permitted cross-origin redirect is followed after revalidation', async () => {
    fixture.writeProfile('forwarding', {
      origins: [fixture.mock.origin, fixture.peer.origin],
      auth: {
        type: 'bearer',
        credential_id: 'mock-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      redirects: {
        max: 3,
        forward_credentials: [{ from: fixture.mock.origin, to: fixture.peer.origin }],
      },
      permissions: [
        { method: 'GET', path: '/redirect/**', decision: 'auto' },
        { method: 'GET', path: '/ok', decision: 'auto' },
      ],
    })
    fixture.repo.commit('add forwarding profile')
    const grants = grantsWith({ token: MOCK_SECRET }, 'forwarding')
    const outcome = await call({ profile: 'forwarding', path: '/redirect/peer' }, { grants })
    expect(outcome.kind).toBe('success')
    expect(fixture.peer.requests.some((entry) => entry.headers.authorization)).toBe(true)
  })
})

describe('reserved headers and parameters', () => {
  test('the enforced set is exactly the one the contract names', () => {
    const profile = readProfile(fixture.repo, 'keyed')
    expect(reservedHeadersFor(profile)).toEqual([...RESERVED_HEADERS, 'authorization'].sort())
    expect([...RESERVED_HEADERS]).toEqual([
      'host',
      'content-length',
      'connection',
      'proxy-connection',
      'keep-alive',
      'te',
      'trailer',
      'transfer-encoding',
      'upgrade',
      'proxy-authorization',
      'proxy-authenticate',
    ])
  })

  test.each([...RESERVED_HEADERS])('a caller setting %s rejects the call', async (name) => {
    const before = fixture.mock.requests.length
    const outcome = await call({ headers: { [name]: 'x' } })
    expect(outcome.kind).toBe('policy_failure')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a caller setting the credential header in any case rejects the call', async () => {
    const grants = grantsWith({ token: MOCK_SECRET }, 'keyed')
    const outcome = await call(
      { profile: 'keyed', path: '/auth', headers: { AuThOrIzAtIoN: 'Bearer nope' } },
      { grants },
    )
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('credential header')
  })

  test('a caller setting the credential query parameter rejects the call', async () => {
    fixture.writeProfile('querykey', {
      auth: {
        type: 'query_key',
        credential_id: 'mock-key',
        components: [{ name: 'key' }],
        placements: [{ kind: 'query', parameter: 'api_key', template: '{key}' }],
      },
      permissions: [{ method: 'GET', path: '/auth', decision: 'auto' }],
    })
    fixture.repo.commit('add querykey profile')
    const grants = grantsWith({ key: MOCK_SECRET }, 'querykey')
    const outcome = await call(
      { profile: 'querykey', path: '/auth', query: { api_key: 'nope' } },
      { grants },
    )
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('credential parameter')
  })

  test('a header value with a control character rejects the call', async () => {
    const outcome = await call({ headers: { 'x-note': 'a\nb' } })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('control character')
  })
})

describe('permissions', () => {
  test('a denied operation resolves no credential and sends no request', async () => {
    const before = fixture.mock.requests.length
    const outcome = await call({ method: 'DELETE', path: '/ok' })
    expect(outcome.kind).toBe('denied')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('an unlisted GET resolves to confirm rather than executing', async () => {
    const before = fixture.mock.requests.length
    const outcome = await call({ path: '/unlisted' })
    expect(outcome.kind).toBe('confirmation_required')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a confirm operation refuses without a channel and sends nothing', async () => {
    const before = fixture.mock.requests.length
    const outcome = await call({
      method: 'POST',
      path: '/echo',
      body: { kind: 'text', value: 'x' },
    })
    expect(outcome.kind).toBe('confirmation_required')
    expect(outcome.preview).toContain('POST')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a declined confirmation sends no request', async () => {
    const before = fixture.mock.requests.length
    const outcome = await call(
      { method: 'POST', path: '/echo', body: { kind: 'text', value: 'x' } },
      { channel: alwaysDecline() },
    )
    expect(outcome.kind).toBe('confirmation_declined')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('an accepted confirmation executes within the same call', async () => {
    const outcome = await call(
      { method: 'POST', path: '/echo', body: { kind: 'json', value: { a: 1 } } },
      { channel: alwaysAccept() },
    )
    expect(outcome.kind).toBe('success')
    expect(outcome.body).toContain('"method":"POST"')
  })
})

describe('responses are bounded and metadata is allowlisted', () => {
  test('an inline overflow reports the bound and writes nothing to disk', async () => {
    fixture.writeProfile('smallinline', {
      response: { inline_max_bytes: 1024, inline_max_compressed_bytes: 1024 },
      permissions: [{ method: 'GET', path: '/large', decision: 'auto' }],
    })
    fixture.repo.commit('add smallinline profile')
    const outcome = await call({ profile: 'smallinline', path: '/large' })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toMatch(/bound/)
  })

  test('a compressed body expanding past the decompressed bound stops the transfer', async () => {
    fixture.writeProfile('smallgzip', {
      response: { inline_max_bytes: 4096, inline_max_compressed_bytes: 8 * 1024 * 1024 },
      permissions: [{ method: 'GET', path: '/compressed-bomb', decision: 'auto' }],
    })
    fixture.repo.commit('add smallgzip profile')
    const outcome = await call({ profile: 'smallgzip', path: '/compressed-bomb' })
    expect(outcome.kind).toBe('policy_failure')
    expect(outcome.message).toContain('decompressed bound')
  })

  test('a timeout is reported and removes any temporary file', async () => {
    fixture.writeProfile('impatient', {
      response: { timeout_ms: 50 },
      permissions: [{ method: 'GET', path: '/slow', decision: 'auto' }],
    })
    fixture.repo.commit('add impatient profile')
    const outcome = await call({ profile: 'impatient', path: '/slow' })
    expect(outcome.kind).toBe('network_failure')
    expect(outcome.message).toContain('bound')
  })

  test('a file response is written owner-only and reports path, type, size and hash', async () => {
    fixture.writeProfile('download', {
      response: { file_max_bytes: 8 * 1024 * 1024 },
      permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
    })
    fixture.repo.commit('add download profile')
    const outcome = await call({ profile: 'download', path: '/ok', responseMode: 'file' })
    expect(outcome.kind).toBe('success')
    expect(outcome.file?.path).toBeTruthy()
    expect(existsSync(outcome.file?.path as string)).toBe(true)
    expect(outcome.file?.hash).toMatch(/^v1:sha256:/)
    expect(outcome.file?.media_type).toContain('application/json')
  })

  test('Set-Cookie and authentication headers never appear in metadata', async () => {
    const outcome = await call({ path: '/cookies' })
    expect(outcome.kind).toBe('success')
    const names = Object.keys(outcome.headers ?? {})
    expect(names).not.toContain('set-cookie')
    expect(names).not.toContain('www-authenticate')
    expect(names).toContain('x-ratelimit-remaining')
    expect(names).not.toContain('x-secret-header')
  })

  test('a remote body that reads as instructions is labeled remote content', async () => {
    const outcome = await call({ path: '/instructions' })
    expect(outcome.kind).toBe('success')
    expect(outcome.remote_content).toBe(true)
    expect(outcome.body).toContain('ignore previous instructions')
    expect(outcome.message).not.toContain('ignore previous instructions')
  })

  test('a 5xx is reported as remote content, not an APImanac refusal', async () => {
    const outcome = await call({ path: '/status/500' })
    expect(outcome.kind).toBe('remote_response')
    expect(outcome.status).toBe(500)
    expect(outcome.remote_content).toBe(true)
  })
})

describe('credential echo containment', () => {
  test('a body echoing the raw token contains and writes no cache entry', async () => {
    const grants = grantsWith({ token: MOCK_SECRET }, 'keyed')
    const cache = ResponseCache.open({ directory: fixture.cacheDir })
    try {
      const outcome = await call({ profile: 'keyed', path: '/echo-credential' }, { grants, cache })
      expect(outcome.kind).toBe('credential_echo_detected')
      expect(outcome.body).toBeUndefined()
      expect(cache.list()).toHaveLength(0)
      expect(JSON.stringify(outcome)).not.toContain(MOCK_SECRET)
    } finally {
      cache.close()
    }
  })

  test('an echo split across two chunks is detected', async () => {
    const grants = grantsWith({ token: MOCK_SECRET }, 'keyed')
    const outcome = await call({ profile: 'keyed', path: '/echo-credential-split' }, { grants })
    expect(outcome.kind).toBe('credential_echo_detected')
    expect(JSON.stringify(outcome)).not.toContain(MOCK_SECRET)
  })

  test('an echo in a response header is detected before allowlisting', async () => {
    const grants = grantsWith({ token: MOCK_SECRET }, 'keyed')
    const outcome = await call({ profile: 'keyed', path: '/echo-credential-header' }, { grants })
    expect(outcome.kind).toBe('credential_echo_detected')
  })

  test('a Basic wire form echo is detected', async () => {
    const grants = grantsWith({ username: MOCK_BASIC_USER, password: MOCK_BASIC_PASSWORD }, 'basic')
    fixture.writeProfile('basicecho', {
      auth: {
        type: 'basic',
        credential_id: 'mock-basic',
        components: [{ name: 'username' }, { name: 'password' }],
        placements: [{ kind: 'basic', username: 'username', password: 'password' }],
      },
      permissions: [{ method: 'GET', path: '/echo-credential', decision: 'auto' }],
    })
    fixture.repo.commit('add basicecho profile')
    const echoGrants = grantsWith(
      { username: MOCK_BASIC_USER, password: MOCK_BASIC_PASSWORD },
      'basicecho',
    )
    void grants
    const outcome = await call(
      { profile: 'basicecho', path: '/echo-credential' },
      { grants: echoGrants },
    )
    expect(outcome.kind).toBe('credential_echo_detected')
  })

  test('a file-mode echo removes the temporary file and returns no path', async () => {
    fixture.writeProfile('echofile', {
      auth: {
        type: 'bearer',
        credential_id: 'mock-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      permissions: [{ method: 'GET', path: '/echo-credential', decision: 'auto' }],
    })
    fixture.repo.commit('add echofile profile')
    const grants = grantsWith({ token: MOCK_SECRET }, 'echofile')
    const outcome = await call(
      { profile: 'echofile', path: '/echo-credential', responseMode: 'file' },
      { grants },
    )
    expect(outcome.kind).toBe('credential_echo_detected')
    expect(outcome.file).toBeUndefined()
  })
})

describe('errors are built without secrets', () => {
  test('a transport failure exposes no credential in raw or encoded form', async () => {
    fixture.writeProfile('deadend', {
      origins: ['http://127.0.0.1:1'],
      auth: {
        type: 'bearer',
        credential_id: 'mock-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
    })
    fixture.repo.commit('add deadend profile')
    const grants = grantsWith({ token: MOCK_SECRET }, 'deadend')
    const outcome = await call({ profile: 'deadend', path: '/ok' }, { grants })
    expect(outcome.kind).toBe('network_failure')
    const serialized = JSON.stringify(outcome)
    expect(serialized).not.toContain(MOCK_SECRET)
    expect(serialized).not.toContain(encodeURIComponent(MOCK_SECRET))
    expect(serialized).not.toContain(Buffer.from(MOCK_SECRET).toString('base64'))
  })

  test('a failing query-key call exposes no credential query value', async () => {
    fixture.writeProfile('querydead', {
      origins: ['http://127.0.0.1:1'],
      auth: {
        type: 'query_key',
        credential_id: 'mock-key',
        components: [{ name: 'key' }],
        placements: [{ kind: 'query', parameter: 'api_key', template: '{key}' }],
      },
      permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
    })
    fixture.repo.commit('add querydead profile')
    const grants = grantsWith({ key: MOCK_SECRET }, 'querydead')
    const outcome = await call({ profile: 'querydead', path: '/ok' }, { grants })
    expect(outcome.kind).toBe('network_failure')
    expect(JSON.stringify(outcome)).not.toContain(MOCK_SECRET)
    expect(JSON.stringify(outcome.request)).not.toContain('api_key')
  })
})

describe('end-to-end calls over the mock', () => {
  test('a no-auth call succeeds with no secret in any output', async () => {
    const outcome = await call({ path: '/ok', query: { a: '1' } })
    expect(outcome.kind).toBe('success')
    expect(outcome.body).toContain('"ok":true')
    expect(JSON.stringify(outcome)).not.toContain(MOCK_SECRET)
  })

  test('a static-auth call with an ephemeral grant and fixture secret succeeds', async () => {
    const grants = grantsWith({ token: MOCK_SECRET }, 'keyed')
    const outcome = await call({ profile: 'keyed', path: '/auth' }, { grants })
    expect(outcome.kind).toBe('success')
    expect(outcome.body).toContain('"authenticated":true')
    expect(JSON.stringify(outcome)).not.toContain(MOCK_SECRET)
  })

  test('a basic-auth call succeeds and leaks neither component', async () => {
    const grants = grantsWith({ username: MOCK_BASIC_USER, password: MOCK_BASIC_PASSWORD }, 'basic')
    const outcome = await call({ profile: 'basic', path: '/auth' }, { grants })
    expect(outcome.kind).toBe('success')
    const serialized = JSON.stringify(outcome)
    expect(serialized).not.toContain(MOCK_BASIC_PASSWORD)
    expect(serialized).not.toContain(
      Buffer.from(`${MOCK_BASIC_USER}:${MOCK_BASIC_PASSWORD}`).toString('base64'),
    )
  })
})

describe('review authority refuses working-tree edits', () => {
  test('an untracked profile is refused naming the file', async () => {
    // Written and never committed, so no later fixture commit can adopt it.
    fixture.writeProfile('nevercommitted', {})
    try {
      const outcome = await call({ profile: 'nevercommitted' })
      expect(outcome.kind).toBe('ineligible')
      expect(outcome.message).toContain(profilePath('mock', 'nevercommitted'))
      expect(outcome.message).toContain('never been committed')
    } finally {
      fixture.repo.remove(profilePath('mock', 'nevercommitted'))
    }
  })

  test('a working-tree edit widening a permission refuses the call', async () => {
    const before = fixture.mock.requests.length
    fixture.writeProfile('widened', {
      permissions: [{ method: 'DELETE', path: '/**', decision: 'deny' }],
    })
    fixture.repo.commit('add widened profile')
    fixture.writeProfile('widened', {
      permissions: [{ method: 'DELETE', path: '/**', decision: 'auto' }],
    })
    const outcome = await call({ profile: 'widened', method: 'DELETE', path: '/ok' })
    expect(outcome.kind).toBe('ineligible')
    expect(outcome.message).toContain('differs from the committed snapshot')
    expect(outcome.message).toContain('permissions')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('a working-tree origin change refuses and sends to neither origin', async () => {
    fixture.writeProfile('originedit', {})
    fixture.repo.commit('add originedit profile')
    const before = fixture.mock.requests.length
    const peerBefore = fixture.peer.requests.length
    fixture.writeProfile('originedit', { origins: [fixture.peer.origin] })
    const outcome = await call({ profile: 'originedit' })
    expect(outcome.kind).toBe('ineligible')
    expect(fixture.mock.requests.length).toBe(before)
    expect(fixture.peer.requests.length).toBe(peerBefore)
  })

  test('a deleted profile is refused naming the file', async () => {
    fixture.writeProfile('deletable', {})
    fixture.repo.commit('add deletable profile')
    fixture.repo.remove(profilePath('mock', 'deletable'))
    const outcome = await call({ profile: 'deletable' })
    expect(outcome.kind).toBe('ineligible')
    expect(outcome.message).toContain('deleted from the worktree')
  })

  test('an evidence-mismatched profile is refused naming both hashes', async () => {
    fixture.writeProfile('mismatched', {})
    const file = fixture.repo.path(profilePath('mock', 'mismatched'))
    const text = Bun.file(file)
    const contents = await text.text()
    writeFileSync(
      file,
      contents.replace(
        /contract_hash: v1:sha256:[0-9a-f]{64}/,
        `contract_hash: v1:sha256:${'1'.repeat(64)}`,
      ),
    )
    fixture.repo.commit('add mismatched profile')
    const outcome = await call({ profile: 'mismatched' })
    expect(outcome.kind).toBe('ineligible')
    expect(outcome.message).toContain('records evidence for')
  })

  test('a candidate profile is refused and directs the caller to verify', async () => {
    fixture.writeProfile('stillcandidate', {}, false)
    fixture.repo.commit('add candidate profile')
    const before = fixture.mock.requests.length
    const outcome = await call({ profile: 'stillcandidate' })
    expect(outcome.kind).toBe('ineligible')
    expect(outcome.message).toContain('apimanac verify')
    expect(fixture.mock.requests.length).toBe(before)
  })

  test('two calls straddling an edit differ', async () => {
    fixture.writeProfile('straddle', {})
    fixture.repo.commit('add straddle profile')
    expect((await call({ profile: 'straddle' })).kind).toBe('success')
    fixture.writeProfile('straddle', { description: 'edited after the first call' })
    expect((await call({ profile: 'straddle' })).kind).toBe('ineligible')
  })

  test('committing pending evidence makes the profile eligible on the next call', async () => {
    fixture.writeProfile('pending', {}, false)
    fixture.repo.commit('add pending candidate')
    expect((await call({ profile: 'pending' })).kind).toBe('ineligible')
    fixture.writeProfile('pending', {}, true)
    expect((await call({ profile: 'pending' })).kind).toBe('ineligible')
    fixture.repo.commit('commit the evidence')
    expect((await call({ profile: 'pending' })).kind).toBe('success')
  })
})

describe('drafts cannot redirect execution identity', () => {
  test('an uncommitted alias is ignored by execution resolution', async () => {
    fixture.repo.writeYaml('catalog/meta/other.yaml', {
      id: 'other',
      name: 'Other',
      aliases: ['mock-api'],
    })
    try {
      const outcome = await call({ api: 'mock-api', profile: 'public' })
      expect(outcome.kind).toBe('success')
      expect(outcome.api_id).toBe('mock')
    } finally {
      fixture.repo.remove('catalog/meta/other.yaml')
    }
  })
})
