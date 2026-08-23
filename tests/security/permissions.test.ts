import { describe, expect, test } from 'bun:test'
import { ExecutionProfile } from '../../src/schema/execution'
import {
  PatternError,
  isValidPermissionMethod,
  parsePermissionPattern,
} from '../../src/schema/pattern'
import {
  UNMATCHED_DECISION,
  describeOperations,
  evaluatePermission,
  matchesPattern,
} from '../../src/policy/permissions'
import { baseProfileInput, parseProfile } from '../helpers/profile'

type Rule = { method: string; path: string; decision: 'auto' | 'confirm' | 'deny' }

function decide(rules: Rule[], method: string, path: string) {
  return evaluatePermission(parseProfile({ permissions: rules }), method, path)
}

describe('segment-aware pattern matching', () => {
  test('a single-segment wildcard does not span separators', () => {
    const pattern = parsePermissionPattern('/repos/*')
    expect(matchesPattern(pattern, '/repos/a')).toBe(true)
    expect(matchesPattern(pattern, '/repos/a/b')).toBe(false)
    expect(matchesPattern(pattern, '/repos')).toBe(false)
    expect(matchesPattern(pattern, '/repos/')).toBe(false)
  })

  test('a terminal double wildcard spans zero or more segments', () => {
    const pattern = parsePermissionPattern('/repos/**')
    expect(matchesPattern(pattern, '/repos')).toBe(true)
    expect(matchesPattern(pattern, '/repos/a')).toBe(true)
    expect(matchesPattern(pattern, '/repos/a/b/c')).toBe(true)
    expect(matchesPattern(pattern, '/other')).toBe(false)
  })

  test('literal segments match exactly', () => {
    const pattern = parsePermissionPattern('/entrez/eutils/esearch.fcgi')
    expect(matchesPattern(pattern, '/entrez/eutils/esearch.fcgi')).toBe(true)
    expect(matchesPattern(pattern, '/entrez/eutils/efetch.fcgi')).toBe(false)
  })
})

describe('invalid patterns are rejected at validation', () => {
  test.each([
    ['a non-terminal double wildcard', '/a/**/b'],
    ['a double wildcard inside a segment', '/a**b'],
    ['a single wildcard inside a segment', '/a*b'],
    ['an alternation group', '/repos/(a|b)'],
    ['a character class', '/repos/[a-z]+'],
    ['a query', '/a?b=1'],
    ['a fragment', '/a#b'],
    ['a non-slash-prefixed pattern', 'repos/a'],
  ])('%s fails validation naming the rejected pattern', (_label, path) => {
    const result = ExecutionProfile.safeParse(
      baseProfileInput({ permissions: [{ method: 'GET', path, decision: 'auto' }] }),
    )
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(JSON.stringify(result.error.issues)).toContain(path.replace(/\\/g, '\\\\'))
      expect(JSON.stringify(result.error.issues)).toContain('permissions')
    }
  })

  test('the parser reports a PatternError naming the pattern', () => {
    try {
      parsePermissionPattern('/a/**/b')
      throw new Error('expected a rejection')
    } catch (error) {
      expect(error).toBeInstanceOf(PatternError)
      expect((error as PatternError).pattern).toBe('/a/**/b')
      expect((error as PatternError).message).toContain('final segment')
    }
  })
})

describe('methods are uppercase tokens or a wildcard', () => {
  test('a lowercase method fails validation', () => {
    expect(isValidPermissionMethod('get')).toBe(false)
    const result = ExecutionProfile.safeParse(
      baseProfileInput({ permissions: [{ method: 'get', path: '/a', decision: 'auto' }] }),
    )
    expect(result.success).toBe(false)
    if (!result.success) expect(JSON.stringify(result.error.issues)).toContain('uppercase')
  })

  test('an uppercase token and a wildcard both pass', () => {
    expect(isValidPermissionMethod('DELETE')).toBe(true)
    expect(isValidPermissionMethod('*')).toBe(true)
    expect(
      ExecutionProfile.safeParse(
        baseProfileInput({
          permissions: [
            { method: 'DELETE', path: '/a', decision: 'deny' },
            { method: '*', path: '/**', decision: 'confirm' },
          ],
        }),
      ).success,
    ).toBe(true)
  })
})

describe('deny always wins', () => {
  test('a broad deny beats a more specific auto', () => {
    const outcome = decide(
      [
        { method: '*', path: '/**', decision: 'deny' },
        { method: 'GET', path: '/repos/a/b', decision: 'auto' },
      ],
      'GET',
      '/repos/a/b',
    )
    expect(outcome.decision).toBe('deny')
    expect(outcome.matched).toHaveLength(2)
    expect(outcome.reason).toContain('denies')
  })

  test('a denied operation is denied even when the deny rule is the least specific', () => {
    expect(
      decide(
        [
          { method: 'DELETE', path: '/**', decision: 'deny' },
          { method: 'DELETE', path: '/repos/*/*', decision: 'auto' },
          { method: 'DELETE', path: '/repos/a/b', decision: 'auto' },
        ],
        'DELETE',
        '/repos/a/b',
      ).decision,
    ).toBe('deny')
  })
})

describe('specificity ordering', () => {
  test('an exact-method rule beats a wildcard-method rule', () => {
    const outcome = decide(
      [
        { method: '*', path: '/repos/*/*', decision: 'auto' },
        { method: 'DELETE', path: '/repos/*/*', decision: 'confirm' },
      ],
      'DELETE',
      '/repos/a/b',
    )
    expect(outcome.decision).toBe('confirm')
    expect(outcome.rule?.method).toBe('DELETE')
  })

  test('more literal segments beats fewer', () => {
    const outcome = decide(
      [
        { method: 'GET', path: '/repos/*/*', decision: 'confirm' },
        { method: 'GET', path: '/repos/a/*', decision: 'auto' },
      ],
      'GET',
      '/repos/a/b',
    )
    expect(outcome.decision).toBe('auto')
    expect(outcome.rule?.path).toBe('/repos/a/*')
  })

  test('a single wildcard beats a terminal double wildcard', () => {
    const outcome = decide(
      [
        { method: 'GET', path: '/repos/**', decision: 'confirm' },
        { method: 'GET', path: '/repos/*', decision: 'auto' },
      ],
      'GET',
      '/repos/a',
    )
    expect(outcome.decision).toBe('auto')
    expect(outcome.rule?.path).toBe('/repos/*')
  })

  test('a greater segment count breaks a remaining tie', () => {
    const outcome = decide(
      [
        { method: 'GET', path: '/**', decision: 'confirm' },
        { method: 'GET', path: '/*/*/**', decision: 'auto' },
      ],
      'GET',
      '/a/b/c',
    )
    expect(outcome.rule?.path).toBe('/*/*/**')
  })
})

describe('an exact tie resolves to the more restrictive decision', () => {
  test('confirm beats auto', () => {
    expect(
      decide(
        [
          { method: 'GET', path: '/repos/*', decision: 'auto' },
          { method: 'GET', path: '/repos/*', decision: 'confirm' },
        ],
        'GET',
        '/repos/a',
      ).decision,
    ).toBe('confirm')
  })

  test('deny beats confirm', () => {
    expect(
      decide(
        [
          { method: 'GET', path: '/repos/*', decision: 'confirm' },
          { method: 'GET', path: '/repos/*', decision: 'deny' },
        ],
        'GET',
        '/repos/a',
      ).decision,
    ).toBe('deny')
  })
})

describe('the unmatched default is confirm', () => {
  test('the declared default is confirm', () => {
    expect(UNMATCHED_DECISION).toBe('confirm')
  })

  test.each([
    ['GET', '/unlisted'],
    ['HEAD', '/unlisted'],
    ['POST', '/unlisted'],
  ])('an unlisted %s resolves to confirm', (method, path) => {
    const outcome = decide([{ method: 'GET', path: '/known', decision: 'auto' }], method, path)
    expect(outcome.decision).toBe('confirm')
    expect(outcome.rule).toBeUndefined()
    expect(outcome.matched).toEqual([])
    expect(outcome.reason).toContain('requires confirmation')
  })

  test('a profile with no rules at all resolves every operation to confirm', () => {
    const outcome = evaluatePermission(parseProfile({ permissions: [] }), 'GET', '/anything')
    expect(outcome.decision).toBe('confirm')
  })
})

describe('operation listing is bounded', () => {
  const rules: Rule[] = [
    { method: 'GET', path: '/a', decision: 'auto' },
    { method: 'GET', path: '/b', decision: 'auto' },
    { method: 'GET', path: '/c', decision: 'confirm' },
  ]

  test('a limit smaller than the rule count truncates and says so', () => {
    const described = describeOperations(parseProfile({ permissions: rules }), 2)
    expect(described.operations).toHaveLength(2)
    expect(described.truncated).toBe(true)
  })

  test('a limit at or above the rule count does not truncate', () => {
    const described = describeOperations(parseProfile({ permissions: rules }), 3)
    expect(described.operations).toHaveLength(3)
    expect(described.truncated).toBe(false)
    expect(described.operations[2]?.decision).toBe('confirm')
  })
})
