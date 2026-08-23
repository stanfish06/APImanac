import { describe, expect, test } from 'bun:test'
import {
  type ApprovalToken,
  ApprovalTokens,
  confirmRequest,
  testChannel,
  ttyChannel,
} from '../../src/execute/confirm'
import { type SanitizedRequest, previewOf, requestBindingText } from '../../src/execute/sanitize'

const REQUEST: SanitizedRequest = {
  api_id: 'mock',
  profile_id: 'keyed',
  account: 'primary',
  method: 'POST',
  origin: 'https://api.example.com',
  path: '/works',
  query: [['per-page', '1']],
  header_names: ['x-note'],
  body: { content_type: 'application/json', bytes: 7, hash: `v1:sha256:${'a'.repeat(64)}` },
  response_mode: 'inline',
  redirect_policy_hash: 'b'.repeat(64),
}

function clock(start = 1_000): { now: () => number; advance: (ms: number) => void } {
  let value = start
  return {
    now: () => value,
    advance: (ms) => {
      value += ms
    },
  }
}

describe('the confirmation channel is injected', () => {
  test('the TTY channel is not constructed without a controlling terminal', () => {
    expect(ttyChannel({ isTTY: false } as unknown as NodeJS.ReadStream)).toBeUndefined()
  })

  test('the TTY channel is constructed when stdin is a terminal', () => {
    const channel = ttyChannel({ isTTY: true } as unknown as NodeJS.ReadStream)
    expect(channel?.label).toBe('tty')
  })

  test('no argv or environment input reaches the confirmation module', async () => {
    const source = await Bun.file(
      Bun.fileURLToPath(new URL('../../src/execute/confirm.ts', import.meta.url)),
    ).text()
    expect(source).not.toContain('process.argv')
    expect(source).not.toContain('process.env')
  })

  test('the test channel is reachable only through the library API', () => {
    expect(testChannel(true).label).toBe('test')
  })
})

describe('the sanitized preview', () => {
  const preview = previewOf(REQUEST)

  test('carries method, origin, path, query, header names, body summary and response mode', () => {
    expect(preview.summary).toContain('POST https://api.example.com/works?per-page=1')
    expect(preview.summary).toContain('mock/keyed')
    expect(preview.summary).toContain('primary')
    expect(preview.summary).toContain('x-note')
    expect(preview.summary).toContain('application/json, 7 byte(s)')
    expect(preview.summary).toContain('response mode: inline')
  })

  test('carries no credential value, authenticated URL, or token material', () => {
    const serialized = JSON.stringify(preview)
    expect(serialized).not.toContain('Authorization')
    expect(serialized).not.toContain('api_key')
    expect(serialized).not.toContain('nonce')
    expect(serialized).not.toContain('binding')
  })

  test('a body-less request says so rather than omitting the field', () => {
    const { body: _body, ...withoutBody } = REQUEST
    expect(previewOf(withoutBody as SanitizedRequest).summary).toContain('body: no body')
  })
})

describe('approval tokens', () => {
  test('a token is 32 random bytes and two mints differ', () => {
    const tokens = new ApprovalTokens('session')
    const first = tokens.mint(REQUEST)
    const second = tokens.mint(REQUEST)
    expect(first.nonce.byteLength).toBe(32)
    expect(first.nonce.equals(second.nonce)).toBe(false)
  })

  test('a token is consumed exactly once', () => {
    const tokens = new ApprovalTokens('session')
    const token = tokens.mint(REQUEST)
    expect(tokens.consume(token, REQUEST).ok).toBe(true)
    const replay = tokens.consume(token, REQUEST)
    expect(replay.ok).toBe(false)
    if (!replay.ok) expect(replay.code).toBe('replayed')
  })

  test.each([
    ['the method', { method: 'GET' }],
    ['the path', { path: '/authors' }],
    ['the query', { query: [['per-page', '2']] as SanitizedRequest['query'] }],
    ['the account', { account: 'other' }],
    ['the permitted headers', { header_names: ['x-note', 'x-extra'] }],
    ['the body hash', { body: { ...REQUEST.body!, hash: `v1:sha256:${'c'.repeat(64)}` } }],
    ['the response mode', { response_mode: 'file' as const }],
    ['the redirect policy hash', { redirect_policy_hash: 'd'.repeat(64) }],
    ['the profile', { profile_id: 'other' }],
    ['the api', { api_id: 'other' }],
  ])('changing %s after approval invalidates the token', (_label, overrides) => {
    const tokens = new ApprovalTokens('session')
    const token = tokens.mint(REQUEST)
    const mutated = tokens.consume(token, { ...REQUEST, ...overrides } as SanitizedRequest)
    expect(mutated.ok).toBe(false)
    if (!mutated.ok) expect(mutated.code).toBe('rebound')
  })

  test('an expired token refuses and a new confirmation is required', () => {
    const time = clock()
    const tokens = new ApprovalTokens('session', 100, time.now)
    const token = tokens.mint(REQUEST)
    time.advance(101)
    const outcome = tokens.consume(token, REQUEST)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) expect(outcome.code).toBe('expired')
  })

  test('a token does not validate across a session boundary', () => {
    const first = new ApprovalTokens('session-a')
    const second = new ApprovalTokens('session-b')
    const token = first.mint(REQUEST)
    const outcome = second.consume(token, REQUEST)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) expect(outcome.code).toBe('replayed')
  })

  test('no acceptance means no token, and consuming nothing refuses', () => {
    const tokens = new ApprovalTokens('session')
    const outcome = tokens.consume(undefined, REQUEST)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) expect(outcome.code).toBe('unknown')
  })

  test('a caller-supplied token-shaped value is never accepted', () => {
    const tokens = new ApprovalTokens('session')
    const forged = {
      nonce: Buffer.alloc(32, 1),
      binding: Buffer.alloc(32, 2),
      session: 'session',
      expiresAt: Number.MAX_SAFE_INTEGER,
    } as unknown as ApprovalToken
    const outcome = tokens.consume(forged, REQUEST)
    expect(outcome.ok).toBe(false)
    if (!outcome.ok) expect(outcome.code).toBe('replayed')
  })

  test('the binding text covers every field a token is bound to', () => {
    const text = requestBindingText(REQUEST)
    for (const fragment of [
      'mock',
      'keyed',
      'primary',
      'POST',
      'https://api.example.com',
      '/works',
      'per-page',
      'x-note',
      REQUEST.body?.hash as string,
      'inline',
      REQUEST.redirect_policy_hash,
    ]) {
      expect(text).toContain(fragment)
    }
  })
})

describe('confirmRequest mints only after an accept', () => {
  test('a declining channel mints nothing', async () => {
    const tokens = new ApprovalTokens('session')
    const outcome = await confirmRequest(testChannel(false), tokens, REQUEST)
    expect(outcome.accepted).toBe(false)
    expect(outcome.token).toBeUndefined()
    expect(tokens.outstanding).toBe(0)
  })

  test('an accepting channel mints exactly one token', async () => {
    const tokens = new ApprovalTokens('session')
    const outcome = await confirmRequest(testChannel(true), tokens, REQUEST)
    expect(outcome.accepted).toBe(true)
    expect(tokens.outstanding).toBe(1)
    expect(tokens.consume(outcome.token, REQUEST).ok).toBe(true)
  })

  test('the channel sees the sanitized preview, never the request object', async () => {
    let seen = ''
    const channel = testChannel((preview) => {
      seen = JSON.stringify(preview)
      return true
    })
    await confirmRequest(channel, new ApprovalTokens('session'), REQUEST)
    expect(seen).toContain('/works')
    expect(seen).not.toContain('Authorization')
  })
})
