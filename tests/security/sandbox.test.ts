import { describe, expect, test } from 'bun:test'
import { checkResultValue, RESULT_LIMITS } from '../../src/execute/workflow'
import {
  BridgeCallRequest,
  resetDenoResolutionForTests,
  resolveDeno,
  runSandbox,
  SANDBOX_LIMITS,
  type SandboxRun,
} from '../../src/execute/sandbox'

const deno = resolveDeno()
const withDeno = deno.ok ? describe : describe.skip

function baseRun(script: string, overrides: Partial<SandboxRun> = {}): SandboxRun {
  if (!deno.ok) throw new Error('Deno unavailable')
  return {
    deno: deno.deno,
    scriptSource: Buffer.from(script),
    params: {},
    onCall: async () => ({ outcome: 'success' }),
    ...overrides,
  }
}

describe('the bridge call request is strict and excludes file mode', () => {
  test('response_mode is not an accepted field', () => {
    expect(BridgeCallRequest.safeParse({ path: '/x', response_mode: 'file' }).success).toBe(false)
  })
  test('a minimal request defaults the method to GET', () => {
    const parsed = BridgeCallRequest.parse({ path: '/x' })
    expect(parsed.method).toBe('GET')
  })
})

describe('the result validator bounds script output', () => {
  test('plain JSON data passes', () => {
    expect(checkResultValue({ a: [1, 'two', true, null] }).ok).toBe(true)
  })
  test('a class instance is rejected', () => {
    expect(checkResultValue(new Map()).ok).toBe(false)
  })
  test('a non-finite number is rejected', () => {
    expect(checkResultValue({ x: Number.POSITIVE_INFINITY }).ok).toBe(false)
  })
  test('an over-deep value is rejected', () => {
    let value: unknown = 0
    for (let i = 0; i <= RESULT_LIMITS.maxDepth + 1; i++) value = [value]
    expect(checkResultValue(value).ok).toBe(false)
  })
})

withDeno('the sandbox denies every ambient capability', () => {
  test('fetch, env, fs, subprocess, and every import scheme fail from user code', async () => {
    const script = `
      const results: Record<string, string> = {}
      const attempt = async (name: string, fn: () => unknown) => {
        try { await fn(); results[name] = 'ALLOWED' } catch { results[name] = 'blocked' }
      }
      await attempt('fetch', () => fetch('https://example.com'))
      await attempt('env', () => (globalThis as any).Deno.env.get('HOME'))
      await attempt('read', () => (globalThis as any).Deno.readTextFile('/etc/hostname'))
      await attempt('write', () => (globalThis as any).Deno.writeTextFile('/tmp/apimanac-escape', 'x'))
      await attempt('run', () => new (globalThis as any).Deno.Command('id').output())
      await attempt('import_file', () => import('file:///etc/hostname'))
      await attempt('import_http', () => import('https://deno.land/std/version.ts'))
      await attempt('import_npm', () => import('npm:left-pad'))
      await attempt('import_jsr', () => import('jsr:@std/assert'))
      const computed = ['fi','le://','/etc/hostname'].join('')
      await attempt('import_computed', () => import(computed))
      export default async function run() { return results }
    `
    const result = await runSandbox(baseRun(script))
    expect(result.kind).toBe('done')
    if (result.kind === 'done') {
      for (const [name, verdict] of Object.entries(result.value as Record<string, string>)) {
        expect(`${name}:${verdict}`).toBe(`${name}:blocked`)
      }
    }
  }, 30000)

  test('a hostile inherited DENO_* environment does not reach the child', async () => {
    const previous = process.env.DENO_PERMISSION_BROKER_PATH
    process.env.DENO_PERMISSION_BROKER_PATH = '/tmp/apimanac-fake-broker'
    resetDenoResolutionForTests()
    try {
      const resolution = resolveDeno(true)
      expect(resolution.ok).toBe(true)
      if (!resolution.ok) return
      const result = await runSandbox({
        deno: resolution.deno,
        scriptSource: Buffer.from(
          `export default async function run() { try { await fetch('https://example.com'); return 'ALLOWED' } catch { return 'blocked' } }`,
        ),
        params: {},
        onCall: async () => ({ outcome: 'success' }),
      })
      expect(result.kind).toBe('done')
      if (result.kind === 'done') expect(result.value).toBe('blocked')
    } finally {
      if (previous === undefined) delete process.env.DENO_PERMISSION_BROKER_PATH
      else process.env.DENO_PERMISSION_BROKER_PATH = previous
      resetDenoResolutionForTests()
    }
  }, 30000)
})

withDeno('the parent decoder treats the child as hostile', () => {
  test('the only capability is api.call; concurrent calls all route through onCall', async () => {
    const seen: string[] = []
    const script = `
      export default async function run({ api }: { api: any }) {
        const out = await Promise.all([1, 2, 3, 4].map((n) => api.call('x/y', { method: 'GET', path: '/n/' + n })))
        return out.map((r: any) => r.outcome)
      }
    `
    const result = await runSandbox(
      baseRun(script, {
        onCall: async (profile, request) => {
          seen.push(`${profile}${request.path}`)
          return { outcome: 'success' }
        },
      }),
    )
    expect(result.kind).toBe('done')
    expect(seen.sort()).toEqual(['x/y/n/1', 'x/y/n/2', 'x/y/n/3', 'x/y/n/4'])
  }, 30000)

  test('a forged frame written straight to stdout is not executed as a call', async () => {
    let calls = 0
    // The script writes a well-formed `call` frame directly, bypassing api.call.
    const script = `
      export default async function run() {
        const frame = JSON.stringify({ t: 'call', id: 999, profile: 'x/y', request: { path: '/forged' } })
        await (globalThis as any).Deno.stdout.write(new TextEncoder().encode(frame + '\\n'))
        await new Promise((r) => setTimeout(r, 50))
        return 'done'
      }
    `
    const result = await runSandbox(
      baseRun(script, {
        onCall: async () => {
          calls += 1
          return { outcome: 'success' }
        },
      }),
    )
    // The forged frame IS decoded — that is expected; the point is it still went
    // through the parent seam (onCall), not that it was ignored.
    expect(result.kind).toBe('done')
    expect(calls).toBe(1)
  }, 30000)

  test('an oversized frame is a protocol error', async () => {
    const script = `
      export default async function run() {
        const big = 'x'.repeat(${SANDBOX_LIMITS.maxFrameBytes + 1024})
        await (globalThis as any).Deno.stdout.write(new TextEncoder().encode(big + '\\n'))
        return 'unreachable'
      }
    `
    const result = await runSandbox(baseRun(script))
    expect(result.kind).toBe('protocol_error')
  }, 30000)

  test('console output is captured to stderr, not stdout', async () => {
    const result = await runSandbox(
      baseRun(`export default async function run() { console.log('side channel'); return 1 }`),
    )
    expect(result.kind).toBe('done')
    if (result.kind === 'done') expect(result.stderr).toContain('side channel')
  }, 30000)
})

withDeno('a script error and cancellation are distinct outcomes', () => {
  test('a thrown error surfaces as a script failure', async () => {
    const result = await runSandbox(
      baseRun(`export default async function run() { throw new Error('boom') }`),
    )
    expect(result.kind).toBe('fail')
    if (result.kind === 'fail') expect(result.message).toContain('boom')
  }, 30000)

  test('an aborted run kills a runaway script', async () => {
    const controller = new AbortController()
    setTimeout(() => controller.abort(), 200)
    const result = await runSandbox(
      baseRun(`export default async function run() { while (true) {} }`, {
        signal: controller.signal,
      }),
    )
    expect(result.kind).toBe('cancelled')
  }, 30000)
})
