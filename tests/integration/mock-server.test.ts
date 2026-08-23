import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { MOCK_SECRET, type MockServer, startMockServer } from '../fixtures/http/mock-server'

describe('the local mock server', () => {
  let mock: MockServer

  beforeAll(async () => {
    mock = await startMockServer({ slowMs: 50, largeBytes: 512 * 1024 })
  })

  afterAll(() => mock.close())

  test('binds an ephemeral port on 127.0.0.1', () => {
    expect(mock.origin).toMatch(/^http:\/\/127\.0\.0\.1:\d+$/)
    expect(mock.port).toBeGreaterThan(0)
  })

  test('the no-auth endpoint returns its scripted payload', async () => {
    const response = await fetch(mock.url('/ok?a=1'))
    expect(response.status).toBe(200)
    expect(await response.json()).toEqual({ ok: true, path: '/ok', query: { a: '1' } })
  })

  test('the static-auth endpoint accepts exactly the fixture secret', async () => {
    const rejected = await fetch(mock.url('/auth'))
    expect(rejected.status).toBe(401)
    const accepted = await fetch(mock.url('/auth'), {
      headers: { authorization: `Bearer ${MOCK_SECRET}` },
    })
    expect(accepted.status).toBe(200)
    expect(await accepted.json()).toEqual({ ok: true, authenticated: true })
  })

  test('the redirect endpoints emit 302 with the scripted target', async () => {
    const same = await fetch(mock.url('/redirect/same'), { redirect: 'manual' })
    expect(same.status).toBe(302)
    expect(same.headers.get('location')).toBe(mock.url('/ok'))

    const external = await fetch(mock.url('/redirect/external'), { redirect: 'manual' })
    expect(external.headers.get('location')).toBe('https://elsewhere.example/ok')

    const priv = await fetch(mock.url('/redirect/private'), { redirect: 'manual' })
    expect(priv.headers.get('location')).toBe('http://10.0.0.1/ok')

    const chain = await fetch(mock.url('/redirect/chain/3'), { redirect: 'manual' })
    expect(chain.headers.get('location')).toBe(mock.url('/redirect/chain/2'))
  })

  test('the oversized endpoint streams past any inline bound', async () => {
    const response = await fetch(mock.url('/large'))
    const bytes = await response.arrayBuffer()
    expect(bytes.byteLength).toBeGreaterThanOrEqual(512 * 1024)
  })

  test('the slow endpoint delays its response', async () => {
    const started = Date.now()
    await fetch(mock.url('/slow'))
    expect(Date.now() - started).toBeGreaterThanOrEqual(45)
  })

  test('the compressed endpoint sends gzip', async () => {
    const response = await fetch(mock.url('/compressed'))
    expect(response.headers.get('content-encoding')).toBe('gzip')
    expect(await response.json()).toEqual({ ok: true, compressed: true })
  })

  test('the credential-echo endpoints return what was presented', async () => {
    const body = await fetch(mock.url('/echo-credential'), {
      headers: { authorization: `Bearer ${MOCK_SECRET}` },
    })
    expect(await body.json()).toEqual({ seen: MOCK_SECRET })

    const header = await fetch(mock.url('/echo-credential-header'), {
      headers: { 'x-api-key': MOCK_SECRET },
    })
    expect(header.headers.get('x-observed-token')).toBe(MOCK_SECRET)

    const split = await fetch(mock.url('/echo-credential-split'), {
      headers: { authorization: `Bearer ${MOCK_SECRET}` },
    })
    expect(await split.text()).toContain(MOCK_SECRET)
  })

  test('the cookie endpoint sends the headers the allowlist must exclude', async () => {
    const response = await fetch(mock.url('/cookies'))
    expect(response.headers.get('set-cookie')).toContain('session=')
    expect(response.headers.get('www-authenticate')).toBeTruthy()
    expect(response.headers.get('x-ratelimit-remaining')).toBe('42')
  })

  test('the status endpoint returns the requested code, with Retry-After on 503', async () => {
    expect((await fetch(mock.url('/status/429'))).status).toBe(429)
    const unavailable = await fetch(mock.url('/status/503'))
    expect(unavailable.status).toBe(503)
    expect(unavailable.headers.get('retry-after')).toBe('30')
  })

  test('requests are recorded so a test can assert none was sent', async () => {
    const before = mock.requests.length
    await fetch(mock.url('/ok'))
    expect(mock.requests.length).toBe(before + 1)
    expect(mock.requests.at(-1)?.path).toBe('/ok')
  })
})

describe('two mocks form a cross-origin pair', () => {
  test('the redirect target is the peer origin', async () => {
    const peer = await startMockServer()
    const primary = await startMockServer({ peer })
    try {
      const response = await fetch(primary.url('/redirect/peer'), { redirect: 'manual' })
      expect(response.headers.get('location')).toBe(`${peer.origin}/ok`)
      expect(primary.origin).not.toBe(peer.origin)
    } finally {
      await primary.close()
      await peer.close()
    }
  })
})
