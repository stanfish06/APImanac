import { mkdtempSync, readdirSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { HealthStore, classifyObservation } from '../../src/execute/health'
import { LIMITS } from '../../src/policy/limits'

let directory: string
let path: string

beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), 'apimanac-health-'))
  path = join(directory, 'health.db')
})

afterEach(() => rmSync(directory, { recursive: true, force: true }))

describe('every row of the closed status table', () => {
  test.each([
    [200, 'healthy'],
    [201, 'healthy'],
    [204, 'healthy'],
    [299, 'healthy'],
    [301, 'healthy'],
    [302, 'healthy'],
    [307, 'healthy'],
    [401, 'auth_required'],
    [403, 'auth_required'],
    [407, 'auth_required'],
    [429, 'rate_limited'],
    [404, 'degraded'],
    [405, 'degraded'],
    [408, 'degraded'],
    [410, 'degraded'],
    [418, 'degraded'],
    [400, 'degraded'],
    [500, 'degraded'],
    [502, 'degraded'],
    [504, 'degraded'],
  ] as [number, string][])('status %p maps to %s', (status, expected) => {
    expect(classifyObservation({ status })).toBe(expected as never)
  })

  test('503 carrying Retry-After is rate limited, and without it degraded', () => {
    expect(classifyObservation({ status: 503, retryAfter: true })).toBe('rate_limited')
    expect(classifyObservation({ status: 503 })).toBe('degraded')
  })

  test("a probe's declared expected status counts as healthy", () => {
    expect(classifyObservation({ status: 204, expectedStatus: 204 })).toBe('healthy')
    expect(classifyObservation({ status: 418, expectedStatus: 418 })).toBe('healthy')
    expect(classifyObservation({ status: 418, expectedStatus: 200 })).toBe('degraded')
  })

  test('a redirect refused by policy is degraded', () => {
    expect(classifyObservation({ redirectRefused: true })).toBe('degraded')
  })

  test.each([
    'dns',
    'connection',
    'tls',
    'timeout',
  ] as const)('a %s failure is unreachable', (kind) => {
    expect(classifyObservation({ transportFailure: kind })).toBe('unreachable')
  })

  test('a transport failure outranks any status carried alongside it', () => {
    expect(classifyObservation({ status: 200, transportFailure: 'timeout' })).toBe('unreachable')
  })

  test('an observation with no status at all is unknown', () => {
    expect(classifyObservation({})).toBe('unknown')
  })
})

describe('composition is last-write-wins', () => {
  test('a failure after a success replaces rather than averages the state', () => {
    const store = HealthStore.open(path)
    try {
      const first = store.record(
        'mock',
        'public',
        { status: 200 },
        new Date('2026-03-01T00:00:00Z'),
      )
      expect(first.state).toBe('healthy')
      const second = store.record(
        'mock',
        'public',
        { status: 401 },
        new Date('2026-03-02T00:00:00Z'),
      )
      expect(second.state).toBe('auth_required')
      const current = store.stateOf('mock', 'public')
      expect(current.state).toBe('auth_required')
      expect(current.last_checked).toBe('2026-03-02T00:00:00.000Z')
      expect(current.last_checked > first.last_checked).toBe(true)
    } finally {
      store.close()
    }
  })

  test('a 401 records auth_required rather than unreachable, because the remote answered', () => {
    const store = HealthStore.open(path)
    try {
      expect(store.record('mock', 'public', { status: 401 }).state).toBe('auth_required')
    } finally {
      store.close()
    }
  })

  test('a transient DNS failure records unreachable for that observation only', () => {
    const store = HealthStore.open(path)
    try {
      store.record('mock', 'public', { status: 200 })
      store.record('mock', 'public', { transportFailure: 'dns' })
      expect(store.stateOf('mock', 'public').state).toBe('unreachable')
      store.record('mock', 'public', { status: 200 })
      expect(store.stateOf('mock', 'public').state).toBe('healthy')
    } finally {
      store.close()
    }
  })

  test('a profile with no retained observation reports unknown rather than being omitted', () => {
    const store = HealthStore.open(path)
    try {
      const state = store.stateOf('never', 'called')
      expect(state.state).toBe('unknown')
      expect(state.api_id).toBe('never')
      expect(state.last_checked).toBe('')
    } finally {
      store.close()
    }
  })

  test('two profiles keep separate state', () => {
    const store = HealthStore.open(path)
    try {
      store.record('mock', 'public', { status: 200 })
      store.record('mock', 'keyed', { status: 429 })
      expect(store.stateOf('mock', 'public').state).toBe('healthy')
      expect(store.stateOf('mock', 'keyed').state).toBe('rate_limited')
    } finally {
      store.close()
    }
  })
})

describe('observations are machine-local and bounded', () => {
  test('the store writes only under its given path', () => {
    const store = HealthStore.open(path)
    try {
      store.record('mock', 'public', { status: 200 })
    } finally {
      store.close()
    }
    const unexpected = readdirSync(directory).filter((name) => !name.startsWith('health.db'))
    expect(unexpected).toEqual([])
  })

  test('retention keeps at most the configured window and the newest still decides', () => {
    const store = HealthStore.open(path)
    try {
      const total = LIMITS.healthObservationsPerProfile + 12
      for (let i = 0; i < total; i++) {
        store.record('mock', 'public', { status: 200 })
      }
      expect(store.count('mock', 'public')).toBe(LIMITS.healthObservationsPerProfile)
      store.record('mock', 'public', { status: 429 })
      expect(store.count('mock', 'public')).toBe(LIMITS.healthObservationsPerProfile)
      expect(store.stateOf('mock', 'public').state).toBe('rate_limited')
    } finally {
      store.close()
    }
  })

  test('last_checked is the health observation time and carries no catalog verified_at', () => {
    const store = HealthStore.open(path)
    try {
      const record = store.record(
        'mock',
        'public',
        { status: 200 },
        new Date('2026-04-01T12:00:00Z'),
      )
      expect(record.last_checked).toBe('2026-04-01T12:00:00.000Z')
      expect(Object.keys(record).sort()).toEqual(['api_id', 'last_checked', 'profile_id', 'state'])
    } finally {
      store.close()
    }
  })

  test('a reopened store still reports the last observation', () => {
    const first = HealthStore.open(path)
    first.record('mock', 'public', { status: 403 })
    first.close()
    const second = HealthStore.open(path)
    try {
      expect(second.stateOf('mock', 'public').state).toBe('auth_required')
    } finally {
      second.close()
    }
  })
})
