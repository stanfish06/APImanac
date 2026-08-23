import { credentialFieldNames, type ExecutionProfile } from '../schema/execution'

/**
 * Fields a caller may never set. The set is compared case-insensitively and is
 * exactly what `specs/execution/` — Caller headers and parameters cannot reach
 * reserved fields — names, plus the profile's own credential header and query
 * parameter names.
 */

export const RESERVED_HEADERS = [
  'host',
  'content-length',
  'connection',
  'proxy-connection',
  'keep-alive',
  'te',
  'trailer',
  'transfer-encoding',
  'upgrade',
  'proxy-authorization',
  'proxy-authenticate',
] as const

export type ReservedRejectionCode =
  | 'reserved_header'
  | 'credential_header'
  | 'credential_query'
  | 'control_character'

export interface ReservedRejection {
  readonly code: ReservedRejectionCode
  readonly field: string
  readonly message: string
}

function hasControlCharacter(text: string): boolean {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    if (code < 0x20 || code === 0x7f) return true
  }
  return false
}

/**
 * Check caller-supplied headers and query parameters. A value targeting a
 * reserved field rejects the call rather than being silently dropped.
 */
export function checkCallerFields(
  profile: ExecutionProfile,
  headers: Readonly<Record<string, string>> = {},
  query: Readonly<Record<string, string>> = {},
): ReservedRejection | undefined {
  const credential = credentialFieldNames(profile)
  const credentialHeaders = new Set(credential.headers.map((name) => name.toLowerCase()))
  const credentialQueries = new Set(credential.queries.map((name) => name.toLowerCase()))
  const reserved = new Set<string>(RESERVED_HEADERS)

  for (const [name, value] of Object.entries(headers)) {
    const lower = name.toLowerCase()
    if (hasControlCharacter(name) || hasControlCharacter(value)) {
      return {
        code: 'control_character',
        field: name,
        message: `header \`${name}\` carries a control character`,
      }
    }
    if (credentialHeaders.has(lower)) {
      return {
        code: 'credential_header',
        field: name,
        message: `header \`${name}\` is this profile's credential header and cannot be set by a caller`,
      }
    }
    if (reserved.has(lower)) {
      return {
        code: 'reserved_header',
        field: name,
        message: `header \`${name}\` is reserved and cannot be set by a caller`,
      }
    }
  }

  for (const [name, value] of Object.entries(query)) {
    if (hasControlCharacter(name) || hasControlCharacter(value)) {
      return {
        code: 'control_character',
        field: name,
        message: `query parameter \`${name}\` carries a control character`,
      }
    }
    if (credentialQueries.has(name.toLowerCase())) {
      return {
        code: 'credential_query',
        field: name,
        message: `query parameter \`${name}\` is this profile's credential parameter and cannot be set by a caller`,
      }
    }
  }
  return undefined
}

/** The full reserved header set for this profile, as the test enumerates it. */
export function reservedHeadersFor(profile: ExecutionProfile): string[] {
  return [
    ...RESERVED_HEADERS,
    ...credentialFieldNames(profile).headers.map((name) => name.toLowerCase()),
  ].sort()
}
