import { describe, expect, test } from 'bun:test'
import {
  confirmScript,
  escapeForPreview,
  ScriptApprovals,
  scriptBindingText,
  scriptPreview,
  type ScriptApprovalSubject,
} from '../../src/execute/confirm'

const DIGEST = `v1:sha256:${'a'.repeat(64)}`

function subject(overrides: Partial<ScriptApprovalSubject> = {}): ScriptApprovalSubject {
  return {
    source: Buffer.from('export default async function run() { return 1 }'),
    params: { prompt: 'a cat' },
    bindings: [{ profile: 'fal/keyed', blob_sha256: DIGEST }],
    runtime: 'deno/2.9.6',
    ...overrides,
  }
}

const accept = { label: 'test' as const, confirm: async () => true }
const decline = { label: 'test' as const, confirm: async () => false }

describe('an ad-hoc approval binds an exact subject', () => {
  test('the approved token is consumed against the same subject', () => {
    const approvals = new ScriptApprovals('s')
    const token = approvals.mint(subject())
    expect(approvals.consume(token, subject()).ok).toBe(true)
  })

  test('a token is single-use', () => {
    const approvals = new ScriptApprovals('s')
    const token = approvals.mint(subject())
    expect(approvals.consume(token, subject()).ok).toBe(true)
    expect(approvals.consume(token, subject()).ok).toBe(false)
  })

  test('a changed source cannot consume the token', () => {
    const approvals = new ScriptApprovals('s')
    const token = approvals.mint(subject())
    const mutated = subject({
      source: Buffer.from('export default async function run() { return 2 }'),
    })
    const check = approvals.consume(token, mutated)
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.code).toBe('rebound')
  })

  test('changed params or bindings cannot consume the token', () => {
    const approvals = new ScriptApprovals('s')
    const paramToken = approvals.mint(subject())
    expect(approvals.consume(paramToken, subject({ params: { prompt: 'a dog' } })).ok).toBe(false)
    const bindToken = approvals.mint(subject())
    expect(
      approvals.consume(bindToken, subject({ bindings: [{ profile: 'x/y', blob_sha256: DIGEST }] }))
        .ok,
    ).toBe(false)
  })

  test('the binding text digests the source rather than embedding it', () => {
    const text = scriptBindingText(subject())
    expect(text).not.toContain('export default')
    expect(text).toContain('source_sha256')
  })
})

describe('the preview cannot visually conceal different code', () => {
  test('bidi override and control characters are escaped', () => {
    const escaped = escapeForPreview('a‮bc')
    expect(escaped).toBe('a\\u202eb\\u0007c')
  })

  test('newlines and tabs are preserved', () => {
    expect(escapeForPreview('a\n\tb')).toBe('a\n\tb')
  })

  test('the preview shows the full source and the bindings', () => {
    const preview = scriptPreview(subject())
    expect(preview.kind).toBe('script')
    expect(preview.summary).toContain('fal/keyed')
    expect(preview.summary).toContain('export default')
  })
})

describe('confirmScript mints only on accept', () => {
  test('an accept yields a token', async () => {
    const approvals = new ScriptApprovals('s')
    const outcome = await confirmScript(accept, approvals, subject())
    expect(outcome.accepted).toBe(true)
    expect(outcome.token).toBeDefined()
  })

  test('a decline yields no token', async () => {
    const approvals = new ScriptApprovals('s')
    const outcome = await confirmScript(decline, approvals, subject())
    expect(outcome.accepted).toBe(false)
    expect(outcome.token).toBeUndefined()
  })
})
