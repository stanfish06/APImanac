import { describe, expect, test } from 'bun:test'
import type {
  UrlRejection,
  UrlRejectionCode,
  UrlResult,
  ValidatedTarget,
} from '../../src/policy/url'
import {
  isInsideBasePath,
  normalizePercentEncoding,
  validateAbsoluteUrl,
  validateTarget,
} from '../../src/policy/url'

const ORIGINS = ['https://api.example.com', 'https://api.example.com:8443'] as const

function rejectionOf(result: UrlResult): UrlRejection {
  if (result.ok) throw new Error(`expected a rejection, got ${result.target.url}`)
  return result.rejection
}

function targetOf(result: UrlResult): ValidatedTarget {
  if (!result.ok) throw new Error(`expected ok, got ${result.rejection.code}`)
  return result.target
}

function reason(path: string, basePath?: string): UrlRejectionCode {
  return rejectionOf(validateTarget({ path, allowedOrigins: ORIGINS, basePath })).code
}

describe('path shape rejections', () => {
  const cases: readonly (readonly [string, UrlRejectionCode])[] = [
    ['works/W123', 'path_not_slash_prefixed'],
    ['//evil.example/x', 'scheme_relative_path'],
    ['https://evil.example/x', 'absolute_url_in_path'],
    ['http://evil.example/x', 'absolute_url_in_path'],
    ['file:/etc/passwd', 'absolute_url_in_path'],
    ['/x#frag', 'path_contains_fragment'],
    ['/x?a=1', 'path_contains_query'],
    ['/user@host', 'path_contains_userinfo'],
    ['/a\\b', 'path_contains_backslash'],
    ['/a b', 'path_contains_control_character'],
    ['/a\u0000b', 'path_contains_control_character'],
    ['/a\u007Fb', 'path_contains_control_character'],
    ['/a%2', 'invalid_percent_encoding'],
    ['/a%zz', 'invalid_percent_encoding'],
    ['/a%', 'invalid_percent_encoding'],
    ['/a/../b', 'path_traversal'],
    ['/a/./b', 'path_traversal'],
    ['/..', 'path_traversal'],
  ]

  for (const [path, code] of cases) {
    test(`${JSON.stringify(path)} is ${code}`, () => {
      expect(reason(path)).toBe(code)
    })
  }
})

describe('encoded separators and traversal', () => {
  const separators = ['/a%2Fb', '/a%2fb', '/a%5Cb', '/a%252Fb']
  for (const path of separators) {
    test(`${path} is encoded_path_separator with the normalized form`, () => {
      const rejection = rejectionOf(validateTarget({ path, allowedOrigins: ORIGINS }))
      expect(rejection.code).toBe('encoded_path_separator')
      expect(rejection.normalized).toBeDefined()
    })
  }

  test('normalized form uppercases the surviving escape', () => {
    const rejection = rejectionOf(validateTarget({ path: '/a%2fb', allowedOrigins: ORIGINS }))
    expect(rejection.normalized).toBe('/a%2Fb')
  })

  const traversals = ['/a/%2E%2E/b', '/a/%2e./b', '/a/..%2Fb', '/a/%252e%252e/b', '/a/%2f..']
  for (const path of traversals) {
    test(`${path} is encoded_traversal with the normalized form`, () => {
      const rejection = rejectionOf(validateTarget({ path, allowedOrigins: ORIGINS }))
      expect(rejection.code).toBe('encoded_traversal')
      expect(rejection.normalized).toBeDefined()
    })
  }

  test('the double-encoded traversal keeps its escapes in the normalized form', () => {
    const rejection = rejectionOf(
      validateTarget({ path: '/a/%252e%252e/b', allowedOrigins: ORIGINS }),
    )
    expect(rejection.normalized).toBe('/a/%252e%252e/b')
  })
})

describe('normalizePercentEncoding', () => {
  test('decodes unreserved characters only', () => {
    const result = normalizePercentEncoding('/works/%41%2D%7E%30')
    expect(result.ok && result.normalized).toBe('/works/A-~0')
  })

  test('uppercases every other escape', () => {
    const result = normalizePercentEncoding('/a%3ab%20c')
    expect(result.ok && result.normalized).toBe('/a%3Ab%20c')
  })

  test('a well-formed path is unchanged', () => {
    const result = normalizePercentEncoding('/works/W123')
    expect(result.ok && result.normalized).toBe('/works/W123')
  })

  test('a malformed escape is rejected', () => {
    const result = normalizePercentEncoding('/a%2')
    expect(!result.ok && result.rejection.code).toBe('invalid_percent_encoding')
  })
})

describe('isInsideBasePath', () => {
  test('matches on segment boundaries', () => {
    expect(isInsideBasePath('/v1/x', '/v1')).toBe(true)
    expect(isInsideBasePath('/v1', '/v1')).toBe(true)
    expect(isInsideBasePath('/v10/x', '/v1')).toBe(false)
    expect(isInsideBasePath('/v2/x', '/v1')).toBe(false)
    expect(isInsideBasePath('/v1/x', '/v1/')).toBe(true)
  })

  test('an undeclared base path accepts everything', () => {
    expect(isInsideBasePath('/anything', undefined)).toBe(true)
    expect(isInsideBasePath('/anything', '/')).toBe(true)
  })
})

describe('base path enforcement', () => {
  test('a path outside the base path is rejected', () => {
    expect(reason('/v2/x', '/v1')).toBe('outside_base_path')
  })

  test('traversal is rejected rather than resolved back inside the base path', () => {
    expect(reason('/v1/../v2', '/v1')).toBe('path_traversal')
  })

  test('a path inside the base path passes', () => {
    expect(
      targetOf(validateTarget({ path: '/v1/x', allowedOrigins: ORIGINS, basePath: '/v1' })).path,
    ).toBe('/v1/x')
  })
})

describe('origin handling', () => {
  test('an empty allowlist rejects every request', () => {
    expect(rejectionOf(validateTarget({ path: '/works', allowedOrigins: [] })).code).toBe(
      'origin_not_allowed',
    )
  })

  test('an unusable declared origin is rejected', () => {
    expect(
      rejectionOf(validateTarget({ path: '/works', allowedOrigins: ['not a url'] })).code,
    ).toBe('origin_not_allowed')
    expect(
      rejectionOf(validateTarget({ path: '/works', allowedOrigins: ['ftp://api.example.com'] }))
        .code,
    ).toBe('origin_not_allowed')
  })

  test('a non-default port is carried through', () => {
    const target = targetOf(
      validateTarget({ path: '/works', allowedOrigins: ['https://api.example.com:8443'] }),
    )
    expect(target.origin).toBe('https://api.example.com:8443')
    expect(target.port).toBe(8443)
    expect(target.url).toBe('https://api.example.com:8443/works')
  })

  test('a request to an undeclared port is not allowed', () => {
    expect(
      rejectionOf(validateAbsoluteUrl('https://api.example.com:9999/works', ORIGINS)).code,
    ).toBe('origin_not_allowed')
  })
})

describe('query parameters', () => {
  test('a valid request encodes the query canonically and preserves order', () => {
    const target = targetOf(
      validateTarget({
        path: '/works/W123',
        query: { 'per-page': '1', filter: 'a,b' },
        allowedOrigins: ORIGINS,
        basePath: '/works',
      }),
    )
    expect(target.url).toBe('https://api.example.com/works/W123?per-page=1&filter=a%2Cb')
    expect(target.origin).toBe('https://api.example.com')
    expect(target.hostname).toBe('api.example.com')
    expect(target.port).toBe(443)
    expect(target.scheme).toBe('https:')
    expect(target.path).toBe('/works/W123')
    expect(target.query).toEqual([
      ['per-page', '1'],
      ['filter', 'a,b'],
    ])
  })

  test('spaces and plus signs are unambiguous', () => {
    const target = targetOf(
      validateTarget({ path: '/search', query: [['q', 'a b+c']], allowedOrigins: ORIGINS }),
    )
    expect(target.url).toBe('https://api.example.com/search?q=a%20b%2Bc')
  })

  test('an empty or control-bearing parameter name is rejected', () => {
    expect(
      rejectionOf(validateTarget({ path: '/works', query: { '': '1' }, allowedOrigins: ORIGINS }))
        .code,
    ).toBe('query_key_invalid')
    expect(
      rejectionOf(
        validateTarget({ path: '/works', query: [['a\u0001b', '1']], allowedOrigins: ORIGINS }),
      ).code,
    ).toBe('query_key_invalid')
  })

  test('no query means no question mark', () => {
    expect(targetOf(validateTarget({ path: '/works', allowedOrigins: ORIGINS })).url).toBe(
      'https://api.example.com/works',
    )
  })
})

describe('validateAbsoluteUrl', () => {
  test('an allowed origin passes', () => {
    const target = targetOf(validateAbsoluteUrl('https://api.example.com/works', ORIGINS))
    expect(target.url).toBe('https://api.example.com/works')
    expect(target.path).toBe('/works')
  })

  test('another host is rejected', () => {
    expect(rejectionOf(validateAbsoluteUrl('https://elsewhere.example/works', ORIGINS)).code).toBe(
      'origin_not_allowed',
    )
  })

  test('a different scheme is a different origin', () => {
    expect(rejectionOf(validateAbsoluteUrl('http://api.example.com/works', ORIGINS)).code).toBe(
      'origin_not_allowed',
    )
  })

  test('a non-http scheme is rejected', () => {
    expect(rejectionOf(validateAbsoluteUrl('file:///etc/passwd', ORIGINS)).code).toBe(
      'origin_not_allowed',
    )
    expect(rejectionOf(validateAbsoluteUrl('/works', ORIGINS)).code).toBe('origin_not_allowed')
  })

  test('a fragment or userinfo is rejected', () => {
    expect(rejectionOf(validateAbsoluteUrl('https://api.example.com/works#x', ORIGINS)).code).toBe(
      'path_contains_fragment',
    )
    expect(
      rejectionOf(validateAbsoluteUrl('https://user:pw@api.example.com/works', ORIGINS)).code,
    ).toBe('path_contains_userinfo')
  })

  test('an encoded separator in a redirect target is rejected', () => {
    expect(rejectionOf(validateAbsoluteUrl('https://api.example.com/a%2Fb', ORIGINS)).code).toBe(
      'encoded_path_separator',
    )
  })

  test('the base path is enforced on redirect targets', () => {
    expect(
      rejectionOf(validateAbsoluteUrl('https://api.example.com/v2/x', ORIGINS, '/v1')).code,
    ).toBe('outside_base_path')
  })

  test('the query is re-encoded canonically', () => {
    const target = targetOf(
      validateAbsoluteUrl('https://api.example.com/works?filter=a%2Cb&cursor=*', ORIGINS),
    )
    expect(target.query).toEqual([
      ['filter', 'a,b'],
      ['cursor', '*'],
    ])
    expect(target.url).toBe('https://api.example.com/works?filter=a%2Cb&cursor=*')
  })
})
