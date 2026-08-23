/**
 * Typed failures. A policy refusal, a transport failure, and a remote error
 * status are three different things and never collapse into one exit code.
 */

export type ErrorKind =
  // Usage and configuration
  | 'unknown_command'
  | 'usage'
  | 'catalog_root_unresolved'
  | 'unsupported_schema_version'
  // Catalog integrity
  | 'validation_failed'
  | 'not_found'
  // Policy refusals: APImanac declined before or instead of sending a request
  | 'profile_ineligible'
  | 'operation_denied'
  | 'confirmation_required'
  | 'confirmation_declined'
  | 'missing_grant'
  | 'missing_credential'
  | 'unsupported_auth'
  | 'ambiguous_profile'
  | 'ambiguous_account'
  | 'policy_refused'
  | 'unsupported_request'
  | 'credential_echo_detected'
  // The request left the process and something below HTTP failed
  | 'transport_failed'
  | 'response_bound_exceeded'
  // The remote answered with a non-2xx status
  | 'remote_error_status'
  | 'internal'

export const EXIT_CODES = {
  ok: 0,
  error: 1,
  usage: 2,
  policy: 3,
  transport: 4,
  remote: 5,
} as const

export type ExitCode = (typeof EXIT_CODES)[keyof typeof EXIT_CODES]

const POLICY_KINDS = new Set<ErrorKind>([
  'profile_ineligible',
  'operation_denied',
  'confirmation_required',
  'confirmation_declined',
  'missing_grant',
  'missing_credential',
  'unsupported_auth',
  'ambiguous_profile',
  'ambiguous_account',
  'policy_refused',
  'unsupported_request',
  'credential_echo_detected',
])

export function exitCodeFor(kind: ErrorKind): ExitCode {
  if (kind === 'unknown_command' || kind === 'usage') return EXIT_CODES.usage
  if (POLICY_KINDS.has(kind)) return EXIT_CODES.policy
  if (kind === 'transport_failed' || kind === 'response_bound_exceeded') return EXIT_CODES.transport
  if (kind === 'remote_error_status') return EXIT_CODES.remote
  return EXIT_CODES.error
}

export function isPolicyRefusal(kind: ErrorKind): boolean {
  return POLICY_KINDS.has(kind)
}

export interface ErrorDetail {
  readonly file?: string
  readonly field?: string
  /** Structured, credential-free extras a caller can branch on. */
  readonly [key: string]: unknown
}

/** Every failure surfaced by the CLI or the library is one of these. */
export class ApimanacError extends Error {
  constructor(
    readonly kind: ErrorKind,
    message: string,
    readonly detail: ErrorDetail = {},
  ) {
    super(message)
    this.name = 'ApimanacError'
  }

  get exitCode(): ExitCode {
    return exitCodeFor(this.kind)
  }

  toJSON(): { kind: ErrorKind; message: string; detail: ErrorDetail } {
    return { kind: this.kind, message: this.message, detail: this.detail }
  }
}

export function asApimanacError(error: unknown): ApimanacError {
  if (error instanceof ApimanacError) return error
  return new ApimanacError('internal', error instanceof Error ? error.message : String(error))
}
