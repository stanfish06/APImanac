import { createHash } from 'node:crypto'
import type { ExecutionProfile } from '../schema/execution'

/**
 * One canonical normalization, shared by the contract hash, the authority
 * fingerprint, and the derived store, so those three can never disagree.
 *
 * The projection is restricted to strings, booleans, integers, arrays, and
 * objects. Floats and nulls are rejected rather than serialized, so RFC 8785's
 * number and null handling never comes into play.
 */

export type CanonicalValue =
  | string
  | boolean
  | number
  | readonly CanonicalValue[]
  | { readonly [key: string]: CanonicalValue }

export class CanonicalizationError extends Error {
  constructor(
    readonly path: string,
    message: string,
  ) {
    super(`${path || '<root>'}: ${message}`)
    this.name = 'CanonicalizationError'
  }
}

const ESCAPES: Record<string, string> = {
  '"': '\\"',
  '\\': '\\\\',
  '\b': '\\b',
  '\f': '\\f',
  '\n': '\\n',
  '\r': '\\r',
  '\t': '\\t',
}

function serializeString(value: string, path: string): string {
  let out = '"'
  for (let i = 0; i < value.length; i++) {
    const char = value[i] as string
    const code = value.charCodeAt(i)
    const escaped = ESCAPES[char]
    if (escaped) {
      out += escaped
    } else if (code < 0x20) {
      out += `\\u${code.toString(16).padStart(4, '0')}`
    } else if (code >= 0xd800 && code <= 0xdbff) {
      const next = value.charCodeAt(i + 1)
      if (Number.isNaN(next) || next < 0xdc00 || next > 0xdfff) {
        throw new CanonicalizationError(path, 'string contains an unpaired surrogate')
      }
      out += char + (value[i + 1] as string)
      i += 1
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new CanonicalizationError(path, 'string contains an unpaired surrogate')
    } else {
      out += char
    }
  }
  return `${out}"`
}

/** RFC 8785 sorts object keys by their UTF-16 code units. */
function compareKeys(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}

function serialize(value: unknown, path: string): string {
  if (value === null) {
    throw new CanonicalizationError(path, 'null is not representable in the canonical projection')
  }
  switch (typeof value) {
    case 'string':
      return serializeString(value, path)
    case 'boolean':
      return value ? 'true' : 'false'
    case 'number': {
      if (!Number.isInteger(value)) {
        throw new CanonicalizationError(
          path,
          'only integers are representable in the canonical projection',
        )
      }
      if (!Number.isSafeInteger(value)) {
        throw new CanonicalizationError(path, 'integer is outside the safe range')
      }
      if (Object.is(value, -0)) {
        throw new CanonicalizationError(path, 'negative zero is not representable')
      }
      return String(value)
    }
    case 'undefined':
      throw new CanonicalizationError(path, 'undefined reached the serializer')
    default:
      break
  }
  if (Array.isArray(value)) {
    return `[${value.map((item, index) => serialize(item, `${path}[${index}]`)).join(',')}]`
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>).filter(
      ([, item]) => item !== undefined,
    )
    entries.sort(([a], [b]) => compareKeys(a, b))
    const body = entries
      .map(([key, item]) => `${serializeString(key, path)}:${serialize(item, `${path}.${key}`)}`)
      .join(',')
    return `{${body}}`
  }
  throw new CanonicalizationError(path, `unsupported value of type ${typeof value}`)
}

/** Serialize a projected value with RFC 8785 JSON Canonicalization. */
export function canonicalize(value: unknown): string {
  return serialize(value, '')
}

export function sha256Tagged(input: string | Uint8Array): string {
  return `v1:sha256:${createHash('sha256').update(input).digest('hex')}`
}

/** `v1:sha256:<hex>` over the canonical form of a projected value. */
export function canonicalHash(value: unknown): string {
  return sha256Tagged(Buffer.from(canonicalize(value), 'utf8'))
}

/**
 * Drop `undefined` recursively so an absent optional field and an omitted one
 * canonicalize identically. Nulls are left in place so the serializer rejects
 * them rather than silently hiding a contract error.
 */
export function project(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(project)
  if (value !== null && typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      if (item === undefined) continue
      out[key] = project(item)
    }
    return out
  }
  return value
}

/** The contract hash input: the validated profile minus its verification block. */
export function contractProjection(profile: ExecutionProfile): unknown {
  const { verification: _verification, ...rest } = profile
  return project(rest)
}

export function contractHash(profile: ExecutionProfile): string {
  return canonicalHash(contractProjection(profile))
}

/**
 * The authority fingerprint input: exactly what a user is binding a credential
 * to — origins, base path, auth shape and placements, network scope, and the
 * credential-forwarding policy.
 */
export function authorityProjection(profile: ExecutionProfile): unknown {
  return project({
    origins: [...profile.origins].sort(compareKeys),
    base_path: profile.base_path,
    network_scope: profile.network_scope,
    auth: {
      type: profile.auth.type,
      credential_id: profile.auth.credential_id,
      components: [...profile.auth.components].map((component) => component.name).sort(compareKeys),
      placements: profile.auth.placements,
    },
    forward_credentials: [...profile.redirects.forward_credentials].sort((a, b) =>
      compareKeys(`${a.from}>${a.to}`, `${b.from}>${b.to}`),
    ),
  })
}

export function authorityFingerprint(profile: ExecutionProfile): string {
  return canonicalHash(authorityProjection(profile))
}
