import { LIMITS } from './limits'

/**
 * `add`, `refresh`, and specification and documentation fetches have no
 * profile, so they cannot inherit a network scope from one. This policy is a
 * constant: no catalog content widens it, and the presence of a private-scoped
 * profile in the catalog never lets a maintenance fetch reach a private
 * destination.
 */

export interface EgressPolicy {
  readonly label: string
  /** Exact origins a request may target, or undefined to allow any global https origin. */
  readonly allowedOrigins?: readonly string[]
  readonly basePath?: string
  readonly allowPlainHttp: boolean
  readonly allowNonGlobalAddresses: boolean
  readonly maxRedirects: number
  readonly maxResponseBytes: number
  readonly timeoutMs: number
  /** Whether a credential may be attached at all. */
  readonly credentialsPermitted: boolean
}

export const MAINTENANCE_POLICY: EgressPolicy = {
  label: 'maintenance',
  allowPlainHttp: false,
  allowNonGlobalAddresses: false,
  maxRedirects: 3,
  maxResponseBytes: LIMITS.specificationMaxBytes,
  timeoutMs: LIMITS.requestTimeoutMs,
  credentialsPermitted: false,
}
