import { describe, expect, test } from 'bun:test'
import {
  ParamsSchema,
  validateParams,
  WORKFLOW_PARAM_LIMITS,
  WorkflowDefinition,
} from '../../src/schema/workflow'

const DIGEST = `v1:sha256:${'a'.repeat(64)}`

function definition(overrides: Record<string, unknown> = {}) {
  return {
    workflow_id: 'sweep',
    api_id: 'fal',
    bindings: [{ profile: 'fal/keyed', blob_sha256: DIGEST }],
    ...overrides,
  }
}

describe('the workflow definition schema is closed', () => {
  test('a minimal definition parses and defaults params to an empty object schema', () => {
    const parsed = WorkflowDefinition.parse(definition())
    expect(parsed.params).toEqual({ type: 'object' })
    expect(parsed.description).toBe('')
  })

  test('an unknown top-level key is rejected', () => {
    expect(
      WorkflowDefinition.safeParse(definition({ verification: { state: 'verified' } })).success,
    ).toBe(false)
  })

  test('a binding without a digest is rejected', () => {
    expect(
      WorkflowDefinition.safeParse(definition({ bindings: [{ profile: 'fal/keyed' }] })).success,
    ).toBe(false)
  })

  test('a duplicate binding is rejected', () => {
    const bindings = [
      { profile: 'fal/keyed', blob_sha256: DIGEST },
      { profile: 'fal/keyed', blob_sha256: DIGEST },
    ]
    expect(WorkflowDefinition.safeParse(definition({ bindings })).success).toBe(false)
  })

  test('a non-object top-level params schema is rejected', () => {
    expect(WorkflowDefinition.safeParse(definition({ params: { type: 'string' } })).success).toBe(
      false,
    )
  })

  test('cross-API bindings are accepted', () => {
    const bindings = [
      { profile: 'fal/keyed', blob_sha256: DIGEST },
      { profile: 'openrouter/keyed', blob_sha256: DIGEST },
    ]
    expect(WorkflowDefinition.safeParse(definition({ bindings })).success).toBe(true)
  })
})

describe('the params schema subset is closed', () => {
  test('an unknown keyword is a schema error, never silently ignored', () => {
    for (const node of [
      { type: 'string', minLength: 3 },
      { type: 'object', additionalProperties: true },
      { type: 'number', maximum: 10 },
      { type: 'string', pattern: '^a' },
    ]) {
      expect(ParamsSchema.safeParse(node).success).toBe(false)
    }
  })

  test('required must name declared properties', () => {
    expect(
      ParamsSchema.safeParse({ type: 'object', required: ['ghost'], properties: {} }).success,
    ).toBe(false)
  })

  test('enum entries must match the declared type', () => {
    expect(ParamsSchema.safeParse({ type: 'integer', enum: ['three'] }).success).toBe(false)
    expect(ParamsSchema.safeParse({ type: 'string', enum: ['a', 'b'] }).success).toBe(true)
  })

  test('a default must satisfy its own schema', () => {
    expect(ParamsSchema.safeParse({ type: 'integer', default: 'many' }).success).toBe(false)
    expect(ParamsSchema.safeParse({ type: 'integer', default: 4 }).success).toBe(true)
  })

  test('an array declares items and scalars have no properties', () => {
    expect(ParamsSchema.safeParse({ type: 'array' }).success).toBe(false)
    expect(ParamsSchema.safeParse({ type: 'string', properties: {} }).success).toBe(false)
  })
})

const SWEEP_SCHEMA = ParamsSchema.parse({
  type: 'object',
  required: ['prompt', 'seeds'],
  properties: {
    prompt: { type: 'string' },
    seeds: { type: 'array', items: { type: 'integer' } },
    model: { type: 'string', enum: ['schnell', 'dev'], default: 'schnell' },
  },
})

describe('parameter validation normalizes and fails early', () => {
  test('defaults are applied and the normalized value is returned', () => {
    const check = validateParams(SWEEP_SCHEMA, { prompt: 'a cat', seeds: [1, 2] })
    expect(check.ok).toBe(true)
    if (check.ok) expect(check.value).toEqual({ prompt: 'a cat', seeds: [1, 2], model: 'schnell' })
  })

  test('an undeclared property is rejected, never dropped', () => {
    const check = validateParams(SWEEP_SCHEMA, { prompt: 'x', seeds: [], negative: 'y' })
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.issues[0]?.path).toBe('negative')
  })

  test('a missing required property names itself', () => {
    const check = validateParams(SWEEP_SCHEMA, { prompt: 'x' })
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.issues.map((issue) => issue.path)).toContain('seeds')
  })

  test('enum and integer constraints are enforced', () => {
    expect(validateParams(SWEEP_SCHEMA, { prompt: 'x', seeds: [1.5] }).ok).toBe(false)
    expect(validateParams(SWEEP_SCHEMA, { prompt: 'x', seeds: [], model: 'huge' }).ok).toBe(false)
  })

  test('nesting beyond the depth limit is rejected', () => {
    let schema: Record<string, unknown> = { type: 'string' }
    let value: unknown = 'leaf'
    for (let i = 0; i <= WORKFLOW_PARAM_LIMITS.maxDepth + 1; i++) {
      schema = { type: 'object', properties: { deep: schema } }
      value = { deep: value }
    }
    const check = validateParams(ParamsSchema.parse(schema), value)
    expect(check.ok).toBe(false)
    if (!check.ok) expect(check.issues[0]?.message).toContain('depth')
  })

  test('an over-long string parameter is rejected', () => {
    const schema = ParamsSchema.parse({ type: 'object', properties: { text: { type: 'string' } } })
    const check = validateParams(schema, {
      text: 'x'.repeat(WORKFLOW_PARAM_LIMITS.maxStringLength + 1),
    })
    expect(check.ok).toBe(false)
  })
})
