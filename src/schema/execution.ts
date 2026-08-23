import { z } from 'zod'
import { isValidPermissionMethod, parsePermissionPattern } from './pattern'
import { SpecReference } from './metadata'
import {
  AuthType,
  CanonicalId,
  ComponentName,
  NetworkScope,
  PermissionDecision,
  REQUIRED_COMPONENTS,
  VerificationState,
  isExecutableAuthType,
} from './vocab'

/** `v1:sha256:<64 hex>` — the tagged digest form used by hashes and evidence. */
export const HASH_PATTERN = /^v1:sha256:[0-9a-f]{64}$/
export const TaggedHash = z.string().regex(HASH_PATTERN, 'must be a `v1:sha256:<hex>` digest')

export const ORIGIN_PATTERN = /^https?:\/\/[a-z0-9.-]+(?::\d{1,5})?$/

/**
 * An exact origin: scheme, host, optional port. A wildcard, path, query,
 * fragment, or userinfo makes it something other than an origin.
 */
export const Origin = z.string().superRefine((value, ctx) => {
  const reject = (message: string) =>
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: `origin \`${value}\`: ${message}` })
  if (value !== value.trim()) return reject('has surrounding whitespace')
  if (value.includes('*')) return reject('contains a wildcard')
  if (value.includes('@')) return reject('contains userinfo')
  if (value.includes('#')) return reject('contains a fragment')
  if (value.includes('?')) return reject('contains a query')
  if (value !== value.toLowerCase()) return reject('must be lowercase')
  let parsed: URL
  try {
    parsed = new URL(value)
  } catch {
    return reject('is not a parseable absolute URL')
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return reject('must use http or https')
  }
  if (parsed.username || parsed.password) return reject('contains userinfo')
  if (parsed.pathname !== '/' || value.replace(/^https?:\/\//, '').includes('/')) {
    return reject('contains a path')
  }
  if (!ORIGIN_PATTERN.test(value)) return reject('is not scheme://host[:port]')
})

/** A base path: slash-prefixed, no traversal, no query or fragment. */
export const BasePath = z.string().superRefine((value, ctx) => {
  const reject = (message: string) =>
    ctx.addIssue({ code: z.ZodIssueCode.custom, message: `base_path \`${value}\`: ${message}` })
  if (!value.startsWith('/')) return reject('must be slash-prefixed')
  if (value.includes('?') || value.includes('#')) return reject('must contain no query or fragment')
  if (value.includes('\\')) return reject('must contain no backslash')
  if (value.split('/').includes('..')) return reject('must contain no traversal')
  if (value.includes('%')) return reject('must contain no percent encoding')
})

const HEADER_NAME_PATTERN = /^[A-Za-z0-9!#$%&'*+.^_`|~-]+$/
const QUERY_NAME_PATTERN = /^[A-Za-z0-9._~-]+$/

export const HeaderPlacement = z
  .object({
    kind: z.literal('header'),
    header: z.string().regex(HEADER_NAME_PATTERN, 'not a valid header name'),
    /** Wire template referencing declared components as `{name}`. */
    template: z.string().min(1),
  })
  .strict()

export const QueryPlacement = z
  .object({
    kind: z.literal('query'),
    parameter: z.string().regex(QUERY_NAME_PATTERN, 'not a valid query parameter name'),
    template: z.string().min(1),
  })
  .strict()

export const BasicPlacement = z
  .object({
    kind: z.literal('basic'),
    header: z.string().regex(HEADER_NAME_PATTERN).default('Authorization'),
    username: ComponentName,
    password: ComponentName,
  })
  .strict()

export const CredentialPlacement = z.discriminatedUnion('kind', [
  HeaderPlacement,
  QueryPlacement,
  BasicPlacement,
])

export const CredentialComponent = z
  .object({
    name: ComponentName,
    description: z.string().max(300).optional(),
  })
  .strict()

/** `{name}` references. Anything else inside braces is an interpolation attempt. */
const PLACEHOLDER_SCAN = /\{([^}]*)\}/g

export function templatePlaceholders(template: string): string[] {
  const found: string[] = []
  for (const match of template.matchAll(PLACEHOLDER_SCAN)) found.push(match[1] ?? '')
  return found
}

export const ProfileAuth = z
  .object({
    type: AuthType,
    /** Abstract id a local grant binds to. Never a location or a value. */
    credential_id: z.string().min(1).optional(),
    components: z.array(CredentialComponent).default([]),
    placements: z.array(CredentialPlacement).default([]),
    /** Scopes recorded for description; v0 does not negotiate them. */
    scopes: z.array(z.string().min(1)).default([]),
  })
  .strict()
  .superRefine((value, ctx) => {
    const declared = new Set(value.components.map((c) => c.name))
    if (value.type === 'none') {
      if (value.credential_id || value.components.length || value.placements.length) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: 'auth type `none` declares no credential id, components, or placements',
        })
      }
      return
    }
    if (!value.credential_id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['credential_id'],
        message: 'an authenticated profile must declare an abstract credential id',
      })
    }
    if (isExecutableAuthType(value.type)) {
      const required = REQUIRED_COMPONENTS[value.type]
      for (const name of required) {
        if (!declared.has(name)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['components'],
            message: `auth type \`${value.type}\` requires a \`${name}\` component`,
          })
        }
      }
      if (value.placements.length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['placements'],
          message: `auth type \`${value.type}\` requires a credential placement`,
        })
      }
    }
    for (const placement of value.placements) {
      if (placement.kind === 'basic') {
        for (const name of [placement.username, placement.password]) {
          if (!declared.has(name)) {
            ctx.addIssue({
              code: z.ZodIssueCode.custom,
              path: ['placements'],
              message: `placement references undeclared component \`${name}\``,
            })
          }
        }
        continue
      }
      for (const placeholder of templatePlaceholders(placement.template)) {
        if (!declared.has(placeholder)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['placements'],
            message: `placement template references undeclared placeholder \`{${placeholder}}\``,
          })
        }
      }
    }
  })

export const PermissionRule = z
  .object({
    method: z.string().superRefine((value, ctx) => {
      if (!isValidPermissionMethod(value)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `method \`${value}\` must be an uppercase token or \`*\``,
        })
      }
    }),
    path: z.string().superRefine((value, ctx) => {
      try {
        parsePermissionPattern(value)
      } catch (error) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `pattern \`${value}\`: ${(error as Error).message}`,
        })
      }
    }),
    decision: PermissionDecision,
    note: z.string().max(300).optional(),
  })
  .strict()

export const RedirectForwarding = z.object({ from: Origin, to: Origin }).strict()

export const RedirectPolicy = z
  .object({
    max: z.number().int().min(0).max(10).default(5),
    /** Origin pairs inside this profile that may carry the credential across a hop. */
    forward_credentials: z.array(RedirectForwarding).default([]),
  })
  .strict()

export const CachePolicy = z
  .object({
    enabled: z.boolean().default(false),
    ttl_seconds: z.number().int().min(0).default(300),
    /** Non-idempotent operations are never cached unless this is set. */
    allow_mutations: z.boolean().default(false),
  })
  .strict()

export const ResponseBounds = z
  .object({
    inline_max_bytes: z.number().int().positive().optional(),
    inline_max_compressed_bytes: z.number().int().positive().optional(),
    file_max_bytes: z.number().int().positive().optional(),
    timeout_ms: z.number().int().positive().optional(),
    /** Response headers this profile exposes; nothing else is ever returned. */
    allowed_headers: z.array(z.string().regex(HEADER_NAME_PATTERN)).default([]),
  })
  .strict()

export const HealthProbe = z
  .object({
    method: z
      .string()
      .regex(/^[A-Z]+$/)
      .default('GET'),
    path: z.string().startsWith('/'),
    query: z.record(z.string(), z.string()).default({}),
    expect_status: z.number().int().min(100).max(599).default(200),
    expect_body_contains: z.string().max(200).optional(),
  })
  .strict()

export const VerificationEvidence = z
  .object({
    contract_hash: TaggedHash,
    method: z.string().regex(/^[A-Z]+$/),
    path: z.string().startsWith('/'),
    status: z.number().int().min(100).max(599),
    response_hash: TaggedHash,
    timestamp: z.string().min(1),
    tool_version: z.string().min(1),
  })
  .strict()

export const VerificationBlock = z
  .object({
    state: VerificationState.default('candidate'),
    verified_at: z.string().min(1).optional(),
    evidence: VerificationEvidence.optional(),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.state === 'verified' && !value.evidence) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['evidence'],
        message: '`verified` requires a verification evidence block',
      })
    }
    if (value.state === 'candidate' && value.evidence) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['evidence'],
        message: 'a `candidate` profile carries no evidence',
      })
    }
  })

/**
 * Which source supplied each aspect of the profile. A profile is one atomic
 * contract: an auth shape from one source is never combined with an origin from
 * another, so at most one non-manual source may appear here.
 */
export const PROFILE_ASPECTS = [
  'origins',
  'base_path',
  'auth',
  'permissions',
  'network_scope',
  'redirects',
  'cache',
  'response',
  'health_probe',
  'spec_ref',
] as const

export const ProfileProvenance = z.record(z.enum(PROFILE_ASPECTS), z.string().min(1))

export const ExecutionProfile = z
  .object({
    profile_id: CanonicalId,
    api_id: CanonicalId,
    /** The root manifest owns the schema version; a record repeating it is a contract error. */
    schema_version: z.undefined({
      invalid_type_error: 'the root manifest owns the schema version; a record must not repeat it',
    }),
    description: z.string().max(500).default(''),
    provenance: ProfileProvenance.default({}),
    origins: z.array(Origin).min(1),
    base_path: BasePath.optional(),
    auth: ProfileAuth,
    permissions: z.array(PermissionRule).default([]),
    network_scope: NetworkScope.default('public'),
    redirects: RedirectPolicy.default({}),
    cache: CachePolicy.default({}),
    response: ResponseBounds.default({}),
    health_probe: HealthProbe.optional(),
    spec_ref: SpecReference.optional(),
    verification: VerificationBlock.default({}),
  })
  .strict()
  .superRefine((value, ctx) => {
    const sources = new Set(
      Object.values(value.provenance).filter((source) => source && source !== 'manual'),
    )
    if (sources.size > 1) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['provenance'],
        message: `profile composes fields from several sources (${[...sources].sort().join(', ')}); a profile is one atomic contract`,
      })
    }
    const origins = new Set(value.origins)
    if (origins.size !== value.origins.length) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['origins'],
        message: 'duplicate origin',
      })
    }
    for (const pair of value.redirects.forward_credentials) {
      for (const [key, origin] of [
        ['from', pair.from],
        ['to', pair.to],
      ] as const) {
        if (!origins.has(origin)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['redirects', 'forward_credentials'],
            message: `credential forwarding \`${key}\` origin \`${origin}\` is not one of this profile's origins`,
          })
        }
      }
    }
    if (value.health_probe && value.base_path) {
      if (!isInsideBasePath(value.health_probe.path, value.base_path)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['health_probe', 'path'],
          message: 'health probe path is outside the profile base path',
        })
      }
    }
  })

export function isInsideBasePath(path: string, basePath: string): boolean {
  const base = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath
  if (base === '') return true
  return path === base || path.startsWith(`${base}/`)
}

export type Origin = z.infer<typeof Origin>
export type CredentialPlacement = z.infer<typeof CredentialPlacement>
export type CredentialComponent = z.infer<typeof CredentialComponent>
export type ProfileAuth = z.infer<typeof ProfileAuth>
export type PermissionRule = z.infer<typeof PermissionRule>
export type RedirectPolicy = z.infer<typeof RedirectPolicy>
export type CachePolicy = z.infer<typeof CachePolicy>
export type ResponseBounds = z.infer<typeof ResponseBounds>
export type HealthProbe = z.infer<typeof HealthProbe>
export type VerificationEvidence = z.infer<typeof VerificationEvidence>
export type VerificationBlock = z.infer<typeof VerificationBlock>
export type ProfileProvenance = z.infer<typeof ProfileProvenance>
export type ExecutionProfile = z.infer<typeof ExecutionProfile>

/** Header and query names a caller may never set, derived from the profile's placements. */
export function credentialFieldNames(profile: ExecutionProfile): {
  headers: string[]
  queries: string[]
} {
  const headers: string[] = []
  const queries: string[] = []
  for (const placement of profile.auth.placements) {
    if (placement.kind === 'header' || placement.kind === 'basic') headers.push(placement.header)
    else queries.push(placement.parameter)
  }
  return { headers, queries }
}
