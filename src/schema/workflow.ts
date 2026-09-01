import { z } from 'zod'
import { TaggedHash } from './execution'
import { CanonicalId } from './vocab'

/**
 * Workflow definitions: a reviewed composition of profile calls. The yaml is
 * the contract — params schema and pinned bindings — and the sibling `.ts`
 * holds the body. Both are committed and hash-checked before a run.
 */

export const WORKFLOW_PARAM_LIMITS = {
  /** Maximum schema/value nesting. */
  maxDepth: 8,
  /** Maximum total values across one params object. */
  maxMembers: 512,
  /** Maximum length of one string parameter. */
  maxStringLength: 65536,
} as const

/** `<api-id>/<profile-id>` — the only form a binding may name. */
export const BINDING_PROFILE_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*\/[a-z0-9]+(?:-[a-z0-9]+)*$/

export const WorkflowBinding = z
  .object({
    profile: z
      .string()
      .regex(BINDING_PROFILE_PATTERN, 'must be `<api-id>/<profile-id>` in kebab case'),
    /** SHA-256 of the bound profile's committed blob bytes, tagged. */
    blob_sha256: TaggedHash,
  })
  .strict()

const PARAM_TYPES = ['object', 'string', 'number', 'integer', 'boolean', 'array'] as const
export type ParamType = (typeof PARAM_TYPES)[number]

export interface ParamsSchemaNode {
  readonly type: ParamType
  readonly description?: string
  readonly properties?: Readonly<Record<string, ParamsSchemaNode>>
  readonly required?: readonly string[]
  readonly items?: ParamsSchemaNode
  readonly enum?: readonly (string | number | boolean)[]
  readonly default?: unknown
}

/**
 * The closed schema subset. `strict()` makes every unknown keyword a build-time
 * error rather than a silently ignored constraint.
 */
export const ParamsSchema: z.ZodType<ParamsSchemaNode> = z.lazy(() =>
  z
    .object({
      type: z.enum(PARAM_TYPES),
      description: z.string().max(500).optional(),
      properties: z.record(z.string().min(1), ParamsSchema).optional(),
      required: z.array(z.string().min(1)).optional(),
      items: ParamsSchema.optional(),
      enum: z
        .array(z.union([z.string(), z.number(), z.boolean()]))
        .min(1)
        .optional(),
      default: z.unknown().optional(),
    })
    .strict()
    .superRefine((node, ctx) => {
      const reject = (message: string, path: (string | number)[] = []) =>
        ctx.addIssue({ code: z.ZodIssueCode.custom, message, path })
      if (node.type === 'object') {
        if (node.items) reject('`items` applies only to arrays', ['items'])
        if (node.enum) reject('`enum` applies only to scalars', ['enum'])
        const declared = new Set(Object.keys(node.properties ?? {}))
        for (const name of node.required ?? []) {
          if (!declared.has(name))
            reject(`required property \`${name}\` is not declared`, ['required'])
        }
      } else if (node.type === 'array') {
        if (!node.items) reject('an array declares `items`', ['items'])
        if (node.properties || node.required)
          reject('`properties`/`required` apply only to objects')
        if (node.enum) reject('`enum` applies only to scalars', ['enum'])
      } else {
        if (node.properties || node.required)
          reject('`properties`/`required` apply only to objects')
        if (node.items) reject('`items` applies only to arrays', ['items'])
        if (node.enum) {
          for (const entry of node.enum) {
            if (!scalarMatches(node.type, entry)) {
              reject(`enum entry \`${String(entry)}\` does not match type \`${node.type}\``, [
                'enum',
              ])
            }
          }
        }
      }
      if (node.default !== undefined) {
        const check = validateValue(node, node.default, [], { depth: 0, members: 0 }, false)
        if (check.length)
          reject(`default does not satisfy this schema: ${check[0]?.message}`, ['default'])
      }
    }),
)

function scalarMatches(type: ParamType, value: unknown): boolean {
  switch (type) {
    case 'string':
      return typeof value === 'string'
    case 'boolean':
      return typeof value === 'boolean'
    case 'number':
      return typeof value === 'number' && Number.isFinite(value)
    case 'integer':
      return typeof value === 'number' && Number.isInteger(value)
    default:
      return false
  }
}

export const WorkflowDefinition = z
  .object({
    workflow_id: CanonicalId,
    api_id: CanonicalId,
    /** The root manifest owns the schema version; a record repeating it is a contract error. */
    schema_version: z.undefined({
      invalid_type_error: 'the root manifest owns the schema version; a record must not repeat it',
    }),
    description: z.string().max(500).default(''),
    bindings: z.array(WorkflowBinding).min(1),
    params: ParamsSchema.default({ type: 'object' }),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.params.type !== 'object') {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['params'],
        message: 'the top-level params schema must have type `object`',
      })
    }
    const seen = new Set<string>()
    for (const binding of value.bindings) {
      if (seen.has(binding.profile)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['bindings'],
          message: `duplicate binding \`${binding.profile}\``,
        })
      }
      seen.add(binding.profile)
    }
  })

export type WorkflowBinding = z.infer<typeof WorkflowBinding>
export type WorkflowDefinition = z.infer<typeof WorkflowDefinition>

export interface ParamIssue {
  readonly path: string
  readonly message: string
}

interface Budget {
  depth: number
  members: number
}

function issue(path: (string | number)[], message: string): ParamIssue {
  return { path: path.join('.') || '$', message }
}

function validateValue(
  node: ParamsSchemaNode,
  value: unknown,
  path: (string | number)[],
  budget: Budget,
  applyDefaults: boolean,
  out?: { value: unknown },
): ParamIssue[] {
  if (budget.depth > WORKFLOW_PARAM_LIMITS.maxDepth) {
    return [issue(path, `exceeds the maximum nesting depth of ${WORKFLOW_PARAM_LIMITS.maxDepth}`)]
  }
  budget.members += 1
  if (budget.members > WORKFLOW_PARAM_LIMITS.maxMembers) {
    return [issue(path, `exceeds the maximum of ${WORKFLOW_PARAM_LIMITS.maxMembers} values`)]
  }

  switch (node.type) {
    case 'string': {
      if (typeof value !== 'string') return [issue(path, 'must be a string')]
      if (value.length > WORKFLOW_PARAM_LIMITS.maxStringLength) {
        return [issue(path, `exceeds ${WORKFLOW_PARAM_LIMITS.maxStringLength} characters`)]
      }
      if (node.enum && !node.enum.includes(value)) {
        return [issue(path, `must be one of: ${node.enum.join(', ')}`)]
      }
      if (out) out.value = value
      return []
    }
    case 'boolean': {
      if (typeof value !== 'boolean') return [issue(path, 'must be a boolean')]
      if (node.enum && !node.enum.includes(value)) {
        return [issue(path, `must be one of: ${node.enum.join(', ')}`)]
      }
      if (out) out.value = value
      return []
    }
    case 'number':
    case 'integer': {
      if (typeof value !== 'number' || !Number.isFinite(value)) {
        return [issue(path, 'must be a finite number')]
      }
      if (node.type === 'integer' && !Number.isInteger(value)) {
        return [issue(path, 'must be an integer')]
      }
      if (node.enum && !node.enum.includes(value)) {
        return [issue(path, `must be one of: ${node.enum.join(', ')}`)]
      }
      if (out) out.value = value
      return []
    }
    case 'array': {
      if (!Array.isArray(value)) return [issue(path, 'must be an array')]
      const items = node.items
      if (!items) return [issue(path, 'schema declares no `items`')]
      const collected: unknown[] = []
      const issues: ParamIssue[] = []
      for (let i = 0; i < value.length; i++) {
        const slot = out ? { value: undefined as unknown } : undefined
        issues.push(
          ...validateValue(
            items,
            value[i],
            [...path, i],
            { depth: budget.depth + 1, members: budget.members },
            applyDefaults,
            slot,
          ),
        )
        budget.members += 1
        if (slot) collected.push(slot.value)
      }
      if (out) out.value = collected
      return issues
    }
    case 'object': {
      if (typeof value !== 'object' || value === null || Array.isArray(value)) {
        return [issue(path, 'must be an object')]
      }
      const record = value as Record<string, unknown>
      const properties = node.properties ?? {}
      const issues: ParamIssue[] = []
      // Undeclared properties are rejected, never silently dropped.
      for (const key of Object.keys(record)) {
        if (!(key in properties)) issues.push(issue([...path, key], 'is not a declared parameter'))
      }
      const result: Record<string, unknown> = {}
      const required = new Set(node.required ?? [])
      for (const [key, child] of Object.entries(properties)) {
        const present = key in record
        if (!present) {
          if (child.default !== undefined && applyDefaults) {
            result[key] = structuredClone(child.default)
            continue
          }
          if (required.has(key)) issues.push(issue([...path, key], 'is required'))
          continue
        }
        const slot = out ? { value: undefined as unknown } : undefined
        issues.push(
          ...validateValue(
            child,
            record[key],
            [...path, key],
            { depth: budget.depth + 1, members: budget.members },
            applyDefaults,
            slot,
          ),
        )
        if (slot) result[key] = slot.value
      }
      if (out) out.value = result
      return issues
    }
  }
}

export type ParamsCheck =
  | { readonly ok: true; readonly value: Record<string, unknown> }
  | { readonly ok: false; readonly issues: ParamIssue[] }

/**
 * Validate one params object and apply declared defaults. The returned value is
 * the normalized form: it is what an approval binds and what the script sees.
 */
export function validateParams(schema: ParamsSchemaNode, value: unknown): ParamsCheck {
  const input = value ?? {}
  const out = { value: undefined as unknown }
  const issues = validateValue(schema, input, [], { depth: 0, members: 0 }, true, out)
  if (issues.length) return { ok: false, issues }
  return { ok: true, value: out.value as Record<string, unknown> }
}
