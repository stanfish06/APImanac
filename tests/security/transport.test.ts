import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { validateAbsoluteUrl } from '../../src/policy/url'
import { send, type TransportPolicy } from '../../src/execute/transport'
import { EchoScanner, buildNeedles } from '../../src/execute/echo'
import { MOCK_SECRET, type MockServer, startMockServer } from '../fixtures/http/mock-server'

/**
 * The transport pins what it validated: `node:http(s)` with a custom `lookup`
 * that hands back only a validated address, so no second unchecked resolution
 * can happen between validation and connection.
 */

let mock: MockServer
let peer: MockServer

beforeAll(async () => {
  peer = await startMockServer()
  mock = await startMockServer({ peer, slowMs: 300 })
})

afterAll(async () => {
  await mock.close()
  await peer.close()
})

function policy(overrides: Partial<TransportPolicy> = {}): TransportPolicy {
  return {
    allowedOrigins: [mock.origin],
    allowNonGlobalAddresses: true,
    allowPlainHttp: true,
    maxRedirects: 3,
    forwardCredentials: [],
    timeoutMs: 5_000,
    inlineMaxBytes: 1024 * 1024,
    inlineMaxCompressedBytes: 1024 * 1024,
    fileMaxBytes: 1024 * 1024,
    allowedResponseHeaders: ['x-ratelimit-remaining'],
    ...overrides,
  }
}

function target(path: string, origin = mock.origin) {
  const validated = validateAbsoluteUrl(`${origin}${path}`, [origin])
  if (!validated.ok) throw new Error(`fixture target did not validate: ${validated.rejection.code}`)
  return validated.target
}

describe('the connection lands on the validated address', () => {
  test('a request to the validated loopback address reaches the mock', async () => {
    const before = mock.requests.length
    const result = await send(
      {
        method: 'GET',
        target: target('/ok'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy(),
    )
    expect(result.kind).toBe('ok')
    expect(mock.requests.length).toBe(before + 1)
  })

  test('the Host header is the original hostname and port, not the address', async () => {
    await send(
      {
        method: 'GET',
        target: target('/echo'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy(),
    )
    const recorded = mock.requests.at(-1)
    expect(recorded?.headers.host).toBe(`127.0.0.1:${mock.port}`)
  })

  test('a hostname resolving outside the scope is refused with no connection', async () => {
    const before = mock.requests.length
    const result = await send(
      {
        method: 'GET',
        target: target('/ok'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy({ allowNonGlobalAddresses: false }),
    )
    expect(result.kind).toBe('failure')
    if (result.kind === 'failure') {
      expect(result.code).toBe('non_global_address')
      expect(result.policy).toBe(true)
    }
    expect(mock.requests.length).toBe(before)
  })

  test('a validated address that stops listening fails to connect rather than resolving again', async () => {
    const closing = await startMockServer()
    const origin = closing.origin
    await closing.close()
    const result = await send(
      {
        method: 'GET',
        target: target('/ok', origin),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy({ allowedOrigins: [origin] }),
    )
    expect(result.kind).toBe('failure')
    if (result.kind === 'failure') expect(result.code).toBe('connection_failed')
  })
})

describe('plain HTTP and timeouts', () => {
  test('a plain-HTTP target is refused when the policy forbids it', async () => {
    const before = mock.requests.length
    const result = await send(
      {
        method: 'GET',
        target: target('/ok'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy({ allowPlainHttp: false }),
    )
    expect(result.kind).toBe('failure')
    if (result.kind === 'failure') expect(result.code).toBe('plain_http_refused')
    expect(mock.requests.length).toBe(before)
  })

  test('a request past the time bound is aborted and reported as a timeout', async () => {
    const result = await send(
      {
        method: 'GET',
        target: target('/slow'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy({ timeoutMs: 50 }),
    )
    expect(result.kind).toBe('failure')
    if (result.kind === 'failure') expect(result.code).toBe('timeout')
  })
})

describe('redirects are revalidated at every hop', () => {
  test('a bounded chain completes', async () => {
    const result = await send(
      {
        method: 'GET',
        target: target('/redirect/chain/2'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy({ maxRedirects: 5 }),
    )
    expect(result.kind).toBe('ok')
  })

  test('a chain past the bound fails without a further request', async () => {
    const result = await send(
      {
        method: 'GET',
        target: target('/redirect/chain/9'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy({ maxRedirects: 2 }),
    )
    expect(result.kind).toBe('failure')
    if (result.kind === 'failure') {
      expect(result.code).toBe('redirect_limit')
      expect(result.policy).toBe(true)
    }
  })

  test('a redirect target outside the allowed origins is not followed at all', async () => {
    const before = peer.requests.length
    const result = await send(
      {
        method: 'GET',
        target: target('/redirect/peer'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy(),
    )
    expect(result.kind).toBe('failure')
    if (result.kind === 'failure') expect(result.code).toBe('redirect_outside_origins')
    expect(peer.requests.length).toBe(before)
  })

  test('a credentialed hop to a second allowed origin without permission is refused', async () => {
    const before = peer.requests.length
    const result = await send(
      {
        method: 'GET',
        target: target('/redirect/peer'),
        headers: { authorization: `Bearer ${MOCK_SECRET}` },
        responseMode: 'inline',
        credentialed: true,
      },
      policy({ allowedOrigins: [mock.origin, peer.origin] }),
    )
    expect(result.kind).toBe('failure')
    if (result.kind === 'failure') expect(result.code).toBe('redirect_forwarding_not_permitted')
    expect(peer.requests.length).toBe(before)
  })

  test('a permitted credentialed hop carries the credential to that origin', async () => {
    const result = await send(
      {
        method: 'GET',
        target: target('/redirect/peer'),
        headers: { authorization: `Bearer ${MOCK_SECRET}` },
        responseMode: 'inline',
        credentialed: true,
      },
      policy({
        allowedOrigins: [mock.origin, peer.origin],
        forwardCredentials: [{ from: mock.origin, to: peer.origin }],
      }),
    )
    expect(result.kind).toBe('ok')
    expect(peer.requests.at(-1)?.headers.authorization).toBe(`Bearer ${MOCK_SECRET}`)
  })

  test('an uncredentialed hop to a second allowed origin needs no forwarding permission', async () => {
    const result = await send(
      {
        method: 'GET',
        target: target('/redirect/peer'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy({ allowedOrigins: [mock.origin, peer.origin] }),
    )
    expect(result.kind).toBe('ok')
  })
})

describe('response metadata and echoes', () => {
  test('only allowlisted headers plus the payload descriptors are returned', async () => {
    const result = await send(
      {
        method: 'GET',
        target: target('/cookies'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy(),
    )
    expect(result.kind).toBe('ok')
    if (result.kind === 'ok') {
      expect(Object.keys(result.headers).sort()).toEqual([
        'content-length',
        'content-type',
        'x-ratelimit-remaining',
      ])
    }
  })

  test('a compressed body is decoded within the bounds', async () => {
    const result = await send(
      {
        method: 'GET',
        target: target('/compressed'),
        headers: {},
        responseMode: 'inline',
        credentialed: false,
      },
      policy(),
    )
    expect(result.kind).toBe('ok')
    if (result.kind === 'ok') expect(result.body?.toString()).toContain('"compressed":true')
  })

  test('an echo split across chunks is detected by the streamed scanner', async () => {
    const scanner = new EchoScanner(buildNeedles([MOCK_SECRET]))
    const result = await send(
      {
        method: 'GET',
        target: target('/echo-credential-split'),
        headers: { authorization: `Bearer ${MOCK_SECRET}` },
        responseMode: 'inline',
        scanner,
        credentialed: true,
      },
      policy(),
    )
    expect(result.kind).toBe('credential_echo')
    expect(scanner.found).toBe(true)
  })
})
