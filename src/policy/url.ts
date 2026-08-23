/**
 * Target validation for outbound requests. Every rejection here is decidable
 * from the request text alone, so a bad target is refused before any DNS
 * lookup or socket is created.
 */

export type UrlRejectionCode =
  | 'path_not_slash_prefixed'
  | 'absolute_url_in_path'
  | 'scheme_relative_path'
  | 'path_contains_fragment'
  | 'path_contains_query'
  | 'path_contains_userinfo'
  | 'path_contains_backslash'
  | 'path_contains_control_character'
  | 'encoded_path_separator'
  | 'encoded_traversal'
  | 'invalid_percent_encoding'
  | 'path_traversal'
  | 'origin_not_allowed'
  | 'outside_base_path'
  | 'query_key_invalid'

export interface UrlRejection {
  readonly code: UrlRejectionCode
  readonly message: string
  readonly normalized?: string
}

export interface ValidatedTarget {
  readonly origin: string
  readonly path: string
  readonly query: readonly (readonly [string, string])[]
  readonly url: string
  readonly hostname: string
  readonly port: number
  readonly scheme: 'http:' | 'https:'
}

export type UrlResult =
  | { ok: true; target: ValidatedTarget }
  | { ok: false; rejection: UrlRejection }

export interface TargetInput {
  path: string
  /** Which allowed origin to target; defaults to the first declared one. */
  origin?: string
  query?: Readonly<Record<string, string>> | readonly (readonly [string, string])[]
  allowedOrigins: readonly string[]
  basePath?: string
}

const SCHEME_PREFIX = /^[A-Za-z][A-Za-z0-9+.-]*:/
const PERCENT_ESCAPE = /%([0-9A-Fa-f]{2})/g
const HEX_PAIR = /^[0-9A-Fa-f]{2}$/
const UNRESERVED = /^[A-Za-z0-9._~-]$/
const ENCODED_SEPARATOR = /%(2f|5c)/i
const ENCODED_DOT = /%2e/i
const DOT_DOT_SEPARATOR = /(\.\.%(2f|5c)|%(2f|5c)\.\.)/i
/** Index of the first character a URL cannot carry raw, or -1. */
function rawCharacterIndex(text: string, includeSpace: boolean): number {
  for (let i = 0; i < text.length; i++) {
    const code = text.charCodeAt(i)
    if (code < 0x20 || code === 0x7f || (includeSpace && code === 0x20)) return i
  }
  return -1
}

function reject(code: UrlRejectionCode, message: string, normalized?: string): UrlResult {
  return {
    ok: false,
    rejection: normalized === undefined ? { code, message } : { code, message, normalized },
  }
}

function decodeOnce(text: string): string {
  return text.replace(PERCENT_ESCAPE, (_match, hex: string) =>
    String.fromCharCode(Number.parseInt(hex, 16)),
  )
}

function hasEncodedTraversal(text: string): boolean {
  if (DOT_DOT_SEPARATOR.test(text)) return true
  return ENCODED_DOT.test(text) && text.replace(/%2e/gi, '.').includes('..')
}

export function normalizePercentEncoding(
  path: string,
): { ok: true; normalized: string } | { ok: false; rejection: UrlRejection } {
  let normalized = ''
  for (let i = 0; i < path.length; i++) {
    const char = path[i] as string
    if (char !== '%') {
      normalized += char
      continue
    }
    const hex = path.slice(i + 1, i + 3)
    if (!HEX_PAIR.test(hex)) {
      return {
        ok: false,
        rejection: { code: 'invalid_percent_encoding', message: `malformed escape at index ${i}` },
      }
    }
    const decoded = String.fromCharCode(Number.parseInt(hex, 16))
    normalized += UNRESERVED.test(decoded) ? decoded : `%${hex.toUpperCase()}`
    i += 2
  }
  // one extra decoding pass catches double-encoded forms such as %252F
  const once = decodeOnce(path)
  if (hasEncodedTraversal(path) || hasEncodedTraversal(once)) {
    return {
      ok: false,
      rejection: { code: 'encoded_traversal', message: 'path encodes a `..` segment', normalized },
    }
  }
  if (ENCODED_SEPARATOR.test(path) || ENCODED_SEPARATOR.test(once)) {
    return {
      ok: false,
      rejection: {
        code: 'encoded_path_separator',
        message: 'path encodes a separator',
        normalized,
      },
    }
  }
  return { ok: true, normalized }
}

export function isInsideBasePath(path: string, basePath: string | undefined): boolean {
  if (!basePath || basePath === '/') return true
  const base = basePath.endsWith('/') ? basePath.slice(0, -1) : basePath
  return path === base || path.startsWith(`${base}/`)
}

/** Runs the text-only path rules and returns the canonical path. */
function checkPath(
  path: string,
): { ok: true; path: string } | { ok: false; rejection: UrlRejection } {
  if (SCHEME_PREFIX.test(path)) {
    return {
      ok: false,
      rejection: { code: 'absolute_url_in_path', message: 'path must not be an absolute URL' },
    }
  }
  if (path.startsWith('//')) {
    return {
      ok: false,
      rejection: { code: 'scheme_relative_path', message: 'path must not be scheme-relative' },
    }
  }
  if (!path.startsWith('/')) {
    return {
      ok: false,
      rejection: { code: 'path_not_slash_prefixed', message: 'path must start with `/`' },
    }
  }
  if (path.includes('#')) {
    return {
      ok: false,
      rejection: { code: 'path_contains_fragment', message: 'path must not contain `#`' },
    }
  }
  if (path.includes('?')) {
    return {
      ok: false,
      rejection: {
        code: 'path_contains_query',
        message: 'query parameters must be passed separately',
      },
    }
  }
  if (path.includes('@')) {
    return {
      ok: false,
      rejection: { code: 'path_contains_userinfo', message: 'path must not contain `@`' },
    }
  }
  if (path.includes('\\')) {
    return {
      ok: false,
      rejection: { code: 'path_contains_backslash', message: 'path must not contain a backslash' },
    }
  }
  const raw = rawCharacterIndex(path, true)
  if (raw >= 0) {
    const point = path.charCodeAt(raw).toString(16).padStart(4, '0').toUpperCase()
    return {
      ok: false,
      rejection: {
        code: 'path_contains_control_character',
        message: `unencoded U+${point} at index ${raw}`,
      },
    }
  }
  const normalized = normalizePercentEncoding(path)
  if (!normalized.ok) return normalized
  for (const segment of normalized.normalized.split('/')) {
    if (segment === '.' || segment === '..') {
      return {
        ok: false,
        rejection: { code: 'path_traversal', message: 'path contains a `.` or `..` segment' },
      }
    }
  }
  return { ok: true, path: normalized.normalized }
}

function canonicalizeOrigin(origin: string): { origin: string; url: URL } | undefined {
  let url: URL
  try {
    url = new URL(origin)
  } catch {
    return undefined
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') return undefined
  return { origin: url.origin, url }
}

function allowedOriginSet(origins: readonly string[]): Set<string> {
  const allowed = new Set<string>()
  for (const entry of origins) {
    const canonical = canonicalizeOrigin(entry)
    if (canonical) allowed.add(canonical.origin)
  }
  return allowed
}

function toEntries(query: TargetInput['query']): readonly (readonly [string, string])[] {
  if (!query) return []
  return Array.isArray(query)
    ? (query as readonly (readonly [string, string])[])
    : Object.entries(query as Readonly<Record<string, string>>)
}

function buildTarget(
  url: URL,
  path: string,
  entries: readonly (readonly [string, string])[],
): UrlResult {
  for (const [name] of entries) {
    if (name.length === 0 || rawCharacterIndex(name, false) >= 0) {
      return reject(
        'query_key_invalid',
        'query parameter name is empty or holds a control character',
      )
    }
  }
  const encoded = entries
    .map(([name, value]) => `${encodeURIComponent(name)}=${encodeURIComponent(value)}`)
    .join('&')
  const port = url.port === '' ? (url.protocol === 'https:' ? 443 : 80) : Number(url.port)
  return {
    ok: true,
    target: {
      origin: url.origin,
      path,
      query: entries,
      url: `${url.origin}${path}${encoded === '' ? '' : `?${encoded}`}`,
      hostname: url.hostname,
      port,
      scheme: url.protocol as 'http:' | 'https:',
    },
  }
}

export function validateTarget(input: TargetInput): UrlResult {
  const path = checkPath(input.path)
  if (!path.ok) return path
  const allowed = allowedOriginSet(input.allowedOrigins)
  // A relative request carries no origin of its own; it targets the selected
  // allowed origin, or the first declared one.
  const selected = input.origin ?? input.allowedOrigins[0]
  const target = selected === undefined ? undefined : canonicalizeOrigin(selected)
  if (!target || !allowed.has(target.origin)) {
    return reject(
      'origin_not_allowed',
      selected === undefined
        ? 'no allowed origin is declared for this request'
        : `origin \`${selected}\` is not one of this profile's allowed origins`,
    )
  }
  if (!isInsideBasePath(path.path, input.basePath)) {
    return reject('outside_base_path', `path is outside the base path ${input.basePath}`)
  }
  return buildTarget(target.url, path.path, toEntries(input.query))
}

export function validateAbsoluteUrl(
  url: string,
  allowedOrigins: readonly string[],
  basePath?: string,
): UrlResult {
  if (url.includes('#')) {
    return reject('path_contains_fragment', 'url must not carry a fragment')
  }
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return reject('origin_not_allowed', 'url is not absolute')
  }
  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return reject('origin_not_allowed', `scheme ${parsed.protocol} is not http(s)`)
  }
  if (parsed.username !== '' || parsed.password !== '') {
    return reject('path_contains_userinfo', 'url must not carry userinfo')
  }
  if (!allowedOriginSet(allowedOrigins).has(parsed.origin)) {
    return reject('origin_not_allowed', `origin ${parsed.origin} is not allowed`)
  }
  const path = checkPath(parsed.pathname)
  if (!path.ok) return path
  if (!isInsideBasePath(path.path, basePath)) {
    return reject('outside_base_path', `path is outside the base path ${basePath}`)
  }
  const entries: (readonly [string, string])[] = []
  for (const [name, value] of parsed.searchParams) entries.push([name, value])
  return buildTarget(parsed, path.path, entries)
}
