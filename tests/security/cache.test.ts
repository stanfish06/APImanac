import { mkdtempSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { ResponseCache, bodyDigest } from '../../src/execute/cache'
import type { SanitizedRequest } from '../../src/execute/sanitize'

const SECRET = 'fixture-secret-value-0123456789'
const CONTRACT = `v1:sha256:${'a'.repeat(64)}`

function request(overrides: Partial<SanitizedRequest> = {}): SanitizedRequest {
  return {
    api_id: 'mock',
    profile_id: 'public',
    method: 'GET',
    origin: 'https://api.example.com',
    path: '/works',
    query: [['per-page', '1']],
    header_names: [],
    response_mode: 'inline',
    redirect_policy_hash: 'b'.repeat(64),
    ...overrides,
  }
}

function response(body: string, status = 200) {
  return { status, headers: { 'content-type': 'application/json' }, body: Buffer.from(body) }
}

let directory: string

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'apimanac-cache-'))
})

afterEach(() => rmSync(directory, { recursive: true, force: true }))

function open(quotaBytes?: number, now?: () => number) {
  return ResponseCache.open({ directory, quotaBytes, now })
}

describe('caching is opt-in per operation', () => {
  test.each([
    ['GET', false, true],
    ['HEAD', false, true],
    ['POST', false, false],
    ['DELETE', false, false],
    ['PATCH', false, false],
    ['POST', true, true],
  ])('%s with allowMutations=%p is cacheable=%p', (method, allowMutations, expected) => {
    expect(ResponseCache.cacheable(method, allowMutations)).toBe(expected)
  })
})

describe('cache identity is keyed and never persists a secret', () => {
  test('the key file is owner-only', () => {
    const cache = open()
    try {
      expect(cache.keyFileMode()).toBe(0o600)
    } finally {
      cache.close()
    }
  })

  test('the key is machine-local, so two directories key the same request differently', () => {
    const other = mkdtempSync(join(tmpdir(), 'apimanac-cache-other-'))
    const first = open()
    const second = ResponseCache.open({ directory: other })
    try {
      expect(first.identity(request(), CONTRACT)).not.toBe(second.identity(request(), CONTRACT))
    } finally {
      first.close()
      second.close()
      rmSync(other, { recursive: true, force: true })
    }
  })

  test('two accounts issuing the same request key separately', () => {
    const cache = open()
    try {
      expect(cache.identity(request({ account: 'a' }), CONTRACT)).not.toBe(
        cache.identity(request({ account: 'b' }), CONTRACT),
      )
    } finally {
      cache.close()
    }
  })

  test('two bodies key separately', () => {
    const cache = open()
    try {
      const one = request({
        body: { content_type: 'application/json', bytes: 2, hash: bodyDigest(Buffer.from('{}')) },
      })
      const two = request({
        body: {
          content_type: 'application/json',
          bytes: 7,
          hash: bodyDigest(Buffer.from('{"a":1}')),
        },
      })
      expect(cache.identity(one, CONTRACT)).not.toBe(cache.identity(two, CONTRACT))
    } finally {
      cache.close()
    }
  })

  test('two credential query values key separately', () => {
    const cache = open()
    try {
      expect(cache.identity(request(), CONTRACT, [SECRET])).not.toBe(
        cache.identity(request(), CONTRACT, ['other-secret-value']),
      )
    } finally {
      cache.close()
    }
  })

  test('two contract hashes key separately', () => {
    const cache = open()
    try {
      expect(cache.identity(request(), CONTRACT)).not.toBe(
        cache.identity(request(), `v1:sha256:${'c'.repeat(64)}`),
      )
    } finally {
      cache.close()
    }
  })

  test('representation header digests are keyed, not stored', () => {
    const cache = open()
    try {
      const withHeader = cache.identity(request(), CONTRACT, [], [['Accept', SECRET]])
      expect(withHeader).not.toContain(SECRET)
      expect(withHeader).not.toBe(cache.identity(request(), CONTRACT))
    } finally {
      cache.close()
    }
  })

  test('no credential value reaches the identity, the listing, or the index on disk', () => {
    const cache = open()
    try {
      const key = cache.identity(request({ account: SECRET }), CONTRACT, [SECRET])
      expect(key).not.toContain(SECRET)
      cache.write(key, request({ account: 'primary' }), response('{"ok":true}'), 300)
      expect(JSON.stringify(cache.list())).not.toContain(SECRET)
      expect(JSON.stringify(cache.list())).not.toContain('api_key=')
    } finally {
      cache.close()
    }
    const index = readFileSync(join(directory, 'index.db'))
    expect(index.indexOf(Buffer.from(SECRET))).toBe(-1)
  })
})

describe('reads honour the TTL', () => {
  test('an entry inside its TTL is served', () => {
    const cache = open()
    try {
      const key = cache.identity(request(), CONTRACT)
      cache.write(key, request(), response('{"ok":true}'), 300)
      expect(cache.read(key)?.body.toString()).toBe('{"ok":true}')
    } finally {
      cache.close()
    }
  })

  test('a past-TTL entry is not served', () => {
    let time = 1_000
    const cache = open(undefined, () => time)
    try {
      const key = cache.identity(request(), CONTRACT)
      cache.write(key, request(), response('{"ok":true}'), 10)
      expect(cache.read(key)).toBeDefined()
      time += 11_000
      expect(cache.read(key)).toBeUndefined()
    } finally {
      cache.close()
    }
  })

  test('an unknown key reads as a miss', () => {
    const cache = open()
    try {
      expect(cache.read('nope')).toBeUndefined()
    } finally {
      cache.close()
    }
  })
})

describe('the quota is enforced on the write path', () => {
  test('writing past the quota evicts least-recently-used entries until the new one fits', () => {
    let time = 1_000
    const cache = open(300, () => time)
    try {
      for (const name of ['a', 'b', 'c']) {
        cache.write(
          cache.identity(request({ path: `/${name}` }), CONTRACT),
          request(),
          response('x'.repeat(100)),
          300,
        )
        time += 10
      }
      const oldest = cache.identity(request({ path: '/a' }), CONTRACT)
      cache.write(
        cache.identity(request({ path: '/d' }), CONTRACT),
        request(),
        response('x'.repeat(100)),
        300,
      )
      expect(cache.bytes).toBeLessThanOrEqual(300)
      expect(cache.read(oldest)).toBeUndefined()
    } finally {
      cache.close()
    }
  })

  test('the store stays within quota even though prune is never run', () => {
    let time = 1_000
    const cache = open(500, () => time)
    try {
      for (let i = 0; i < 20; i++) {
        cache.write(
          cache.identity(request({ path: `/entry-${i}` }), CONTRACT),
          request(),
          response('y'.repeat(120)),
          300,
        )
        time += 5
        expect(cache.bytes).toBeLessThanOrEqual(500)
      }
    } finally {
      cache.close()
    }
  })

  test('a response larger than the whole quota is not cached and evicts nothing', () => {
    const cache = open(200)
    try {
      const kept = cache.identity(request({ path: '/kept' }), CONTRACT)
      cache.write(kept, request(), response('z'.repeat(100)), 300)
      const oversized = cache.identity(request({ path: '/huge' }), CONTRACT)
      expect(cache.write(oversized, request(), response('z'.repeat(400)), 300)).toBe(false)
      expect(cache.read(kept)).toBeDefined()
      expect(cache.read(oversized)).toBeUndefined()
    } finally {
      cache.close()
    }
  })
})

describe('listing, clearing and pruning', () => {
  test('the listing shows only sanitized origin, path and account labels', () => {
    const cache = open()
    try {
      cache.write(
        cache.identity(request({ account: 'primary' }), CONTRACT),
        request({ account: 'primary' }),
        response('{"ok":true}'),
        300,
      )
      const entries = cache.list()
      expect(entries).toHaveLength(1)
      expect(entries[0]?.origin).toBe('https://api.example.com')
      expect(entries[0]?.path).toBe('/works')
      expect(entries[0]?.account).toBe('primary')
      expect(entries[0]?.profile).toBe('mock/public')
      expect(Object.keys(entries[0] ?? {})).not.toContain('headers')
    } finally {
      cache.close()
    }
  })

  test('clear removes every entry and its body file', () => {
    const cache = open()
    try {
      const key = cache.identity(request(), CONTRACT)
      cache.write(key, request(), response('{"ok":true}'), 300)
      expect(cache.clear()).toBe(1)
      expect(cache.list()).toEqual([])
      expect(cache.bytes).toBe(0)
    } finally {
      cache.close()
    }
  })

  test('prune removes expired entries and reports what it did', () => {
    let time = 1_000
    const cache = open(undefined, () => time)
    try {
      cache.write(
        cache.identity(request({ path: '/short' }), CONTRACT),
        request(),
        response('a'),
        1,
      )
      cache.write(
        cache.identity(request({ path: '/long' }), CONTRACT),
        request(),
        response('b'),
        600,
      )
      time += 5_000
      const result = cache.prune()
      expect(result.expired).toBe(1)
      expect(result.evicted).toBe(0)
      expect(cache.list()).toHaveLength(1)
    } finally {
      cache.close()
    }
  })

  test('prune may shrink the store to quota', () => {
    let time = 1_000
    const cache = ResponseCache.open({ directory, quotaBytes: 10_000, now: () => time })
    try {
      for (let i = 0; i < 5; i++) {
        cache.write(
          cache.identity(request({ path: `/p${i}` }), CONTRACT),
          request(),
          response('c'.repeat(100)),
          600,
        )
        time += 5
      }
      cache.close()
      const tight = ResponseCache.open({ directory, quotaBytes: 250, now: () => time })
      try {
        const result = tight.prune()
        expect(result.evicted).toBeGreaterThan(0)
        expect(tight.bytes).toBeLessThanOrEqual(250)
      } finally {
        tight.close()
      }
    } catch (error) {
      cache.close()
      throw error
    }
  })
})

describe('cached bodies are owner-only', () => {
  test('a body file is written 0600', () => {
    const cache = open()
    try {
      const key = cache.identity(request(), CONTRACT)
      cache.write(key, request(), response('{"ok":true}'), 300)
      expect(statSync(join(directory, `${key}.body`)).mode & 0o777).toBe(0o600)
    } finally {
      cache.close()
    }
  })
})

describe('the orchestrator supplies representation headers', () => {
  test('two requests differing only in Accept key separately', () => {
    const cache = open()
    try {
      const plain = cache.identity(request(), CONTRACT, [])
      const json = cache.identity(request(), CONTRACT, [], [['accept', 'application/json']])
      const xml = cache.identity(request(), CONTRACT, [], [['accept', 'application/xml']])
      expect(new Set([plain, json, xml]).size).toBe(3)
    } finally {
      cache.close()
    }
  })

  test('the call orchestrator passes them, so the slot is not dead', async () => {
    const source = await Bun.file(
      Bun.fileURLToPath(new URL('../../src/execute/call.ts', import.meta.url)),
    ).text()
    expect(source).toContain('representationHeaders(request.headers)')
  })
})
