import type { ExecutionProfile, PermissionRule } from '../schema/execution'
import { type ParsedPattern, parsePermissionPattern } from '../schema/pattern'
import { DECISION_RESTRICTIVENESS, type PermissionDecision } from '../schema/vocab'

/**
 * Permission matching. The most specific matching rule wins, except that a
 * matching `deny` always wins, and an operation matching no rule resolves to
 * `confirm`.
 */

export const UNMATCHED_DECISION: PermissionDecision = 'confirm'

/**
 * Methods a read-only profile denies outright. A `*`-method catch-all would
 * also deny the profile's own `auto` rules, since a matching `deny` always
 * wins; unmatched operations already default to `confirm`.
 */
export const MUTATING_METHODS = ['POST', 'PUT', 'PATCH', 'DELETE'] as const

export interface MatchedRule {
  readonly rule: PermissionRule
  readonly specificity: Specificity
}

export interface PermissionOutcome {
  readonly decision: PermissionDecision
  /** The rule that decided, absent when nothing matched. */
  readonly rule?: PermissionRule
  readonly matched: MatchedRule[]
  readonly reason: string
}

interface Specificity {
  /** 1 when the rule names the method exactly, 0 for `*`. */
  readonly exactMethod: number
  readonly literalSegments: number
  /** 1 when the pattern has no trailing `**`, 0 when it does. */
  readonly bounded: number
  readonly segmentCount: number
}

function specificityOf(rule: PermissionRule, pattern: ParsedPattern): Specificity {
  return {
    exactMethod: rule.method === '*' ? 0 : 1,
    literalSegments: pattern.segments.filter((segment) => segment.kind === 'literal').length,
    bounded: pattern.trailingAny ? 0 : 1,
    segmentCount: pattern.segments.length,
  }
}

/** Ordered: exact method, then literal segments, then `*` over `**`, then segment count. */
function compareSpecificity(a: Specificity, b: Specificity): number {
  if (a.exactMethod !== b.exactMethod) return b.exactMethod - a.exactMethod
  if (a.literalSegments !== b.literalSegments) return b.literalSegments - a.literalSegments
  if (a.bounded !== b.bounded) return b.bounded - a.bounded
  return b.segmentCount - a.segmentCount
}

export function matchesPattern(pattern: ParsedPattern, path: string): boolean {
  const segments = path === '/' ? [''] : path.replace(/^\//, '').split('/')
  if (pattern.trailingAny) {
    if (segments.length < pattern.segments.length) return false
  } else if (segments.length !== pattern.segments.length) {
    return false
  }
  for (let i = 0; i < pattern.segments.length; i++) {
    const expected = pattern.segments[i] as (typeof pattern.segments)[number]
    const actual = segments[i]
    if (actual === undefined) return false
    if (expected.kind === 'literal' && expected.value !== actual) return false
    if (expected.kind === 'single' && actual === '') return false
  }
  return true
}

export function evaluatePermission(
  profile: ExecutionProfile,
  method: string,
  path: string,
): PermissionOutcome {
  const upper = method.toUpperCase()
  const matched: MatchedRule[] = []
  for (const rule of profile.permissions) {
    if (rule.method !== '*' && rule.method !== upper) continue
    let pattern: ParsedPattern
    try {
      pattern = parsePermissionPattern(rule.path)
    } catch {
      continue
    }
    if (!matchesPattern(pattern, path)) continue
    matched.push({ rule, specificity: specificityOf(rule, pattern) })
  }

  if (matched.length === 0) {
    return {
      decision: UNMATCHED_DECISION,
      matched,
      reason: `no rule in ${profile.api_id}/${profile.profile_id} covers ${upper} ${path}, so it requires confirmation`,
    }
  }

  // A matching `deny` wins regardless of how specific the alternatives are.
  const denied = matched.find((entry) => entry.rule.decision === 'deny')
  if (denied) {
    return {
      decision: 'deny',
      rule: denied.rule,
      matched,
      reason: `\`${denied.rule.method} ${denied.rule.path}\` denies ${upper} ${path}`,
    }
  }

  const ordered = [...matched].sort((a, b) => {
    const bySpecificity = compareSpecificity(a.specificity, b.specificity)
    if (bySpecificity !== 0) return bySpecificity
    // An exact tie resolves to the more restrictive decision.
    return DECISION_RESTRICTIVENESS[a.rule.decision] - DECISION_RESTRICTIVENESS[b.rule.decision]
  })
  const winner = ordered[0] as MatchedRule
  return {
    decision: winner.rule.decision,
    rule: winner.rule,
    matched,
    reason: `\`${winner.rule.method} ${winner.rule.path}\` resolves ${upper} ${path} to ${winner.rule.decision}`,
  }
}

/** Bounded operation listing for inspection output. */
export function describeOperations(
  profile: ExecutionProfile,
  limit: number,
): {
  operations: { method: string; path: string; decision: PermissionDecision }[]
  truncated: boolean
} {
  const operations = profile.permissions
    .slice(0, limit)
    .map((rule) => ({ method: rule.method, path: rule.path, decision: rule.decision }))
  return { operations, truncated: profile.permissions.length > limit }
}
