import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import {
  alwaysAccept,
  alwaysDecline,
  executionFixture,
  type ExecutionFixture,
} from '../helpers/execution'
import {
  ApprovalTokens,
  ScriptApprovals,
  type ConfirmationChannel,
} from '../../src/execute/confirm'
import { resolveDeno } from '../../src/execute/sandbox'
import { runScript, runWorkflow, type RunServices } from '../../src/execute/workflow'
import { writeWorkflow } from '../helpers/workflow'

const deno = resolveDeno()
const withDeno = deno.ok ? describe : describe.skip

let fixture: ExecutionFixture

beforeAll(async () => {
  fixture = await executionFixture()
  // A committed workflow that fans out GET /ok through the public profile.
  writeWorkflow(fixture.repo, {
    apiId: 'mock',
    workflowId: 'fan',
    bindings: ['mock/public'],
    params: {
      type: 'object',
      required: ['count'],
      properties: { count: { type: 'integer' } },
    },
    script: `
      export default async function run({ params, api }: { params: any; api: any }) {
        const calls = []
        for (let i = 0; i < params.count; i++) calls.push(api.call('mock/public', { method: 'GET', path: '/ok' }))
        const out = await Promise.all(calls)
        return { statuses: out.map((r: any) => r.status), outcomes: out.map((r: any) => r.outcome) }
      }
    `,
  })
  // A workflow that hits a deny (DELETE) and a confirm (POST /echo). The public
  // profile needs no grant, so this isolates the policy decisions from auth.
  writeWorkflow(fixture.repo, {
    apiId: 'mock',
    workflowId: 'policy',
    bindings: ['mock/public'],
    script: `
      export default async function run({ api }: { api: any }) {
        const del = await api.call('mock/public', { method: 'DELETE', path: '/ok' })
        const confirmed = await api.call('mock/public', { method: 'POST', path: '/echo', body_json: { hi: 1 } })
        return { del: del.outcome, confirmed: confirmed.outcome }
      }
    `,
  })
  // A workflow bound only to mock/public that tries to reach mock/keyed.
  writeWorkflow(fixture.repo, {
    apiId: 'mock',
    workflowId: 'escape',
    bindings: ['mock/public'],
    script: `
      export default async function run({ api }: { api: any }) {
        const r = await api.call('mock/keyed', { method: 'GET', path: '/auth' })
        return { outcome: r.outcome }
      }
    `,
  })
  fixture.repo.commit('committed workflows')
})

afterAll(() => fixture.dispose())

function services(
  channel?: ConfirmationChannel,
  overrides: Partial<RunServices> = {},
): RunServices {
  const base = fixture.services()
  return {
    grants: base.grants,
    tokens: new ApprovalTokens('run-test'),
    scriptApprovals: new ScriptApprovals('run-test'),
    health: base.health,
    channel,
    ...overrides,
  }
}

withDeno('a committed workflow runs through the policy path', () => {
  test('fan-out returns one real result per call', async () => {
    const outcome = await runWorkflow(
      { root: fixture.reopen(), api: 'mock', workflow: 'fan', params: { count: 4 } },
      services(),
    )
    expect(outcome.kind).toBe('success')
    expect(outcome.calls).toBe(4)
    if (outcome.kind === 'success') {
      const result = outcome.result as { statuses: number[]; outcomes: string[] }
      expect(result.statuses).toEqual([200, 200, 200, 200])
      expect(result.outcomes.every((o) => o === 'success')).toBe(true)
    }
  }, 30000)

  test('invalid params refuse before the sandbox starts', async () => {
    const outcome = await runWorkflow(
      { root: fixture.reopen(), api: 'mock', workflow: 'fan', params: { count: 'lots' } },
      services(),
    )
    expect(outcome.kind).toBe('invalid_params')
    expect(outcome.calls).toBe(0)
  })

  test('a deny refuses that call and a confirm elicits per hit', async () => {
    const outcome = await runWorkflow(
      { root: fixture.reopen(), api: 'mock', workflow: 'policy' },
      services(alwaysAccept()),
    )
    expect(outcome.kind).toBe('success')
    if (outcome.kind === 'success') {
      const result = outcome.result as { del: string; confirmed: string }
      expect(result.del).toBe('denied')
      expect(result.confirmed).toBe('success')
    }
  }, 30000)

  test('a declined confirm fails only that call; the script continues', async () => {
    const outcome = await runWorkflow(
      { root: fixture.reopen(), api: 'mock', workflow: 'policy' },
      services(alwaysDecline()),
    )
    expect(outcome.kind).toBe('success')
    if (outcome.kind === 'success') {
      const result = outcome.result as { del: string; confirmed: string }
      expect(result.confirmed).toBe('confirmation_declined')
    }
  }, 30000)

  test('a call to an unbound profile is refused without a request', async () => {
    const outcome = await runWorkflow(
      { root: fixture.reopen(), api: 'mock', workflow: 'escape' },
      services(alwaysAccept()),
    )
    expect(outcome.kind).toBe('success')
    if (outcome.kind === 'success') {
      expect((outcome.result as { outcome: string }).outcome).toBe('unbound_profile')
    }
  }, 30000)
})

describe('ineligibility and missing runtime are reported without running', () => {
  test('an unknown workflow is ineligible', async () => {
    const outcome = await runWorkflow(
      { root: fixture.reopen(), api: 'mock', workflow: 'nonesuch' },
      services(),
    )
    expect(outcome.kind).toBe('ineligible')
  })

  // Runs only in the Deno-absent CI job; asserts graceful degradation there.
  ;(deno.ok ? test.skip : test)(
    'with Deno absent a runnable workflow reports sandbox_unavailable',
    async () => {
      const outcome = await runWorkflow(
        { root: fixture.reopen(), api: 'mock', workflow: 'fan', params: { count: 1 } },
        services(),
      )
      expect(outcome.kind).toBe('sandbox_unavailable')
      expect(outcome.message.toLowerCase()).toContain('deno')
    },
  )
})

withDeno('ad-hoc scripts require source-shown approval', () => {
  test('a declined approval runs nothing', async () => {
    const outcome = await runScript(
      {
        root: fixture.reopen(),
        source: `export default async function run() { return 1 }`,
        bindings: ['mock/public'],
      },
      services(alwaysDecline()),
    )
    expect(outcome.kind).toBe('approval_declined')
    expect(outcome.calls).toBe(0)
  })

  test('an approved ad-hoc script runs under per-call policy', async () => {
    const outcome = await runScript(
      {
        root: fixture.reopen(),
        source: `export default async function run({ api }: { api: any }) {
          const r = await api.call('mock/public', { method: 'GET', path: '/ok' })
          return r.status
        }`,
        bindings: ['mock/public'],
      },
      services(alwaysAccept()),
    )
    expect(outcome.kind).toBe('success')
    if (outcome.kind === 'success') expect(outcome.result).toBe(200)
  }, 30000)

  test('with no channel the run is refused', async () => {
    const outcome = await runScript(
      {
        root: fixture.reopen(),
        source: `export default async function run() { return 1 }`,
        bindings: ['mock/public'],
      },
      services(undefined),
    )
    expect(outcome.kind).toBe('approval_required')
  })

  test('a binding to an uncommitted profile is refused', async () => {
    const outcome = await runScript(
      {
        root: fixture.reopen(),
        source: `export default async function run() { return 1 }`,
        bindings: ['mock/nonexistent'],
      },
      services(alwaysAccept()),
    )
    expect(outcome.kind).toBe('ineligible')
  })
})
