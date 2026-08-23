/**
 * Permission path patterns: slash-prefixed, segment-aware globs. `*` matches one
 * segment, a terminal `**` matches zero or more. Parsing rejects the forms the
 * catalog contract forbids, so an invalid pattern fails validation rather than
 * reaching the matcher.
 */

export type PatternSegment = { kind: 'literal'; value: string } | { kind: 'single' }

export interface ParsedPattern {
  readonly source: string
  readonly segments: readonly PatternSegment[]
  /** True when the pattern ends in `**`, allowing zero or more trailing segments. */
  readonly trailingAny: boolean
}

export class PatternError extends Error {
  constructor(
    readonly pattern: string,
    message: string,
  ) {
    super(message)
    this.name = 'PatternError'
  }
}

const REGEX_HINT = /[()[\]{}+^$|\\]/

export function parsePermissionPattern(pattern: string): ParsedPattern {
  if (!pattern.startsWith('/')) {
    throw new PatternError(pattern, 'pattern must be slash-prefixed')
  }
  if (pattern.includes('?') || pattern.includes('#')) {
    throw new PatternError(pattern, 'pattern must contain no query or fragment')
  }
  if (REGEX_HINT.test(pattern)) {
    throw new PatternError(pattern, 'regular-expression syntax is not a permission pattern')
  }
  const raw = pattern === '/' ? [''] : pattern.slice(1).split('/')
  const segments: PatternSegment[] = []
  let trailingAny = false
  for (let i = 0; i < raw.length; i++) {
    const seg = raw[i] as string
    if (seg === '**') {
      if (i !== raw.length - 1) {
        throw new PatternError(pattern, '`**` is only allowed as the final segment')
      }
      trailingAny = true
      continue
    }
    if (seg.includes('**')) {
      throw new PatternError(pattern, '`**` must be a whole segment')
    }
    if (seg === '*') {
      segments.push({ kind: 'single' })
      continue
    }
    if (seg.includes('*')) {
      throw new PatternError(pattern, '`*` must be a whole segment')
    }
    segments.push({ kind: 'literal', value: seg })
  }
  return { source: pattern, segments, trailingAny }
}

export function isValidPermissionPattern(pattern: string): boolean {
  try {
    parsePermissionPattern(pattern)
    return true
  } catch {
    return false
  }
}

const METHOD_PATTERN = /^[A-Z]+$/

export function isValidPermissionMethod(method: string): boolean {
  return method === '*' || METHOD_PATTERN.test(method)
}
