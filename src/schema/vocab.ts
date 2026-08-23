import { z } from 'zod'

/**
 * The closed vocabularies. Every surface — store, CLI, MCP — imports these
 * declarations rather than restating the values.
 */

export const CURATION_STATES = ['imported', 'curated'] as const
export const LIFECYCLE_STATES = ['active', 'deprecated', 'gone', 'merged'] as const
export const VERIFICATION_STATES = ['candidate', 'verified'] as const
export const NETWORK_SCOPES = ['public', 'private'] as const
export const PERMISSION_DECISIONS = ['auto', 'confirm', 'deny'] as const
export const RESPONSE_MODES = ['inline', 'file'] as const
export const HEALTH_STATES = [
  'unknown',
  'healthy',
  'auth_required',
  'rate_limited',
  'degraded',
  'unreachable',
] as const
export const CREDENTIAL_READINESS = [
  'not_required',
  'ready',
  'no_grant',
  'missing_component',
  'fingerprint_mismatch',
  'unsupported_auth',
  'ambiguous_account',
] as const

/** Auth types this version can actually execute. */
export const EXECUTABLE_AUTH_TYPES = ['none', 'bearer', 'header_key', 'query_key', 'basic'] as const
/** Auth types the catalog may describe but v0 refuses to execute. */
export const DESCRIBABLE_AUTH_TYPES = ['oauth2', 'signed', 'custom'] as const
export const AUTH_TYPES = [...EXECUTABLE_AUTH_TYPES, ...DESCRIBABLE_AUTH_TYPES] as const

export const CurationState = z.enum(CURATION_STATES)
export const Lifecycle = z.enum(LIFECYCLE_STATES)
export const VerificationState = z.enum(VERIFICATION_STATES)
export const NetworkScope = z.enum(NETWORK_SCOPES)
export const PermissionDecision = z.enum(PERMISSION_DECISIONS)
export const ResponseMode = z.enum(RESPONSE_MODES)
export const HealthState = z.enum(HEALTH_STATES)
export const CredentialReadiness = z.enum(CREDENTIAL_READINESS)
export const AuthType = z.enum(AUTH_TYPES)
export const ExecutableAuthType = z.enum(EXECUTABLE_AUTH_TYPES)

export type CurationState = z.infer<typeof CurationState>
export type Lifecycle = z.infer<typeof Lifecycle>
export type VerificationState = z.infer<typeof VerificationState>
export type NetworkScope = z.infer<typeof NetworkScope>
export type PermissionDecision = z.infer<typeof PermissionDecision>
export type ResponseMode = z.infer<typeof ResponseMode>
export type HealthState = z.infer<typeof HealthState>
export type CredentialReadiness = z.infer<typeof CredentialReadiness>
export type AuthType = z.infer<typeof AuthType>
export type ExecutableAuthType = z.infer<typeof ExecutableAuthType>

export function isExecutableAuthType(value: AuthType): value is ExecutableAuthType {
  return (EXECUTABLE_AUTH_TYPES as readonly string[]).includes(value)
}

/** Restrictive-first order used to break permission specificity ties. */
export const DECISION_RESTRICTIVENESS: Record<PermissionDecision, number> = {
  deny: 0,
  confirm: 1,
  auto: 2,
}

export const CANONICAL_ID_PATTERN = /^[a-z0-9]+(?:-[a-z0-9]+)*$/

export const CanonicalId = z
  .string()
  .regex(CANONICAL_ID_PATTERN, 'must be a lowercase kebab slug matching [a-z0-9]+(-[a-z0-9]+)*')

/**
 * The one slug normalization. Manual `add` and every adapter share it, so they
 * cannot disagree about what a name becomes. Returns '' when the result is not
 * a canonical id.
 */
export function slugify(text: string): string {
  const slug = text
    .toLowerCase()
    .normalize('NFKD')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
  return CANONICAL_ID_PATTERN.test(slug) ? slug : ''
}

/** Credential component names a profile may declare and a grant must supply. */
export const COMPONENT_NAME_PATTERN = /^[a-z][a-z0-9_]*$/
export const ComponentName = z
  .string()
  .regex(COMPONENT_NAME_PATTERN, 'must be a lowercase identifier')

/** Components each executable auth type requires, in placement order. */
export const REQUIRED_COMPONENTS: Record<z.infer<typeof ExecutableAuthType>, readonly string[]> = {
  none: [],
  bearer: ['token'],
  header_key: ['key'],
  query_key: ['key'],
  basic: ['username', 'password'],
}
