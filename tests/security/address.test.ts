import { describe, expect, test } from 'bun:test'
import type { AddressScope } from '../../src/policy/address'
import {
  classifyAddress,
  describeAddressScope,
  isGlobalAddress,
  parseAddress,
} from '../../src/policy/address'

const scopeOf = (text: string): AddressScope | undefined => parseAddress(text)?.scope

describe('alternate IPv4 textual forms', () => {
  const loopbackForms = [
    '127.0.0.1',
    '0x7f.0x0.0x0.0x1',
    '0x7f.1',
    '0177.0.0.1',
    '2130706433',
    '127.1',
    '0x7f000001',
  ]

  for (const form of loopbackForms) {
    test(`${form} parses to 127.0.0.1 and is loopback`, () => {
      const parsed = parseAddress(form)
      expect(parsed?.family).toBe(4)
      expect(Array.from(parsed?.bytes ?? [])).toEqual([127, 0, 0, 1])
      expect(parsed?.scope).toBe('loopback')
      expect(isGlobalAddress(form)).toBe(false)
    })
  }

  test('3-part form fills the low bytes with the last part', () => {
    expect(Array.from(parseAddress('192.168.1')?.bytes ?? [])).toEqual([192, 168, 0, 1])
  })

  test('out-of-range parts are not addresses', () => {
    expect(parseAddress('256.0.0.1')).toBeUndefined()
    expect(parseAddress('127.0.0.0.1')).toBeUndefined()
    expect(parseAddress('08.0.0.1')).toBeUndefined()
    expect(parseAddress('127.0.0.')).toBeUndefined()
  })

  test('hostnames are not addresses', () => {
    expect(parseAddress('api.example.com')).toBeUndefined()
    expect(parseAddress('localhost')).toBeUndefined()
    expect(isGlobalAddress('api.example.com')).toBe(false)
  })
})

describe('IPv4 scopes', () => {
  const cases: readonly (readonly [string, AddressScope])[] = [
    ['10.0.0.1', 'private'],
    ['172.16.0.1', 'private'],
    ['172.31.255.255', 'private'],
    ['192.168.1.1', 'private'],
    ['100.64.0.1', 'private'],
    ['172.32.0.1', 'global'],
    ['8.8.8.8', 'global'],
    ['1.1.1.1', 'global'],
    ['169.254.169.254', 'link_local'],
    ['0.0.0.0', 'unspecified'],
    ['224.0.0.1', 'multicast'],
    ['239.255.255.250', 'multicast'],
    ['240.0.0.1', 'reserved'],
    ['255.255.255.255', 'reserved'],
    ['192.0.0.1', 'reserved'],
    ['192.0.2.5', 'reserved'],
    ['198.18.0.1', 'reserved'],
    ['198.51.100.7', 'reserved'],
    ['203.0.113.9', 'reserved'],
  ]

  for (const [text, scope] of cases) {
    test(`${text} is ${scope}`, () => {
      expect(scopeOf(text)).toBe(scope)
      expect(isGlobalAddress(text)).toBe(scope === 'global')
    })
  }
})

describe('IPv6 scopes', () => {
  const cases: readonly (readonly [string, AddressScope])[] = [
    ['::1', 'loopback'],
    ['::', 'unspecified'],
    ['fc00::1', 'private'],
    ['fd00::1', 'private'],
    ['fe80::1', 'link_local'],
    ['ff02::1', 'multicast'],
    ['64:ff9b::8.8.8.8', 'reserved'],
    ['100::1', 'reserved'],
    ['2001:db8::1', 'reserved'],
    ['2001::1', 'reserved'],
    ['2606:4700::1111', 'global'],
    ['2001:4860:4860::8888', 'global'],
  ]

  for (const [text, scope] of cases) {
    test(`${text} is ${scope}`, () => {
      expect(parseAddress(text)?.family).toBe(6)
      expect(scopeOf(text)).toBe(scope)
      expect(isGlobalAddress(text)).toBe(scope === 'global')
    })
  }
})

describe('IPv4-mapped IPv6', () => {
  test('::ffff:127.0.0.1 and ::ffff:7f00:1 are the same loopback address', () => {
    const dotted = parseAddress('::ffff:127.0.0.1')
    const hex = parseAddress('::ffff:7f00:1')
    expect(dotted?.scope).toBe('loopback')
    expect(hex?.scope).toBe('loopback')
    expect(Array.from(hex?.bytes ?? [])).toEqual(Array.from(dotted?.bytes ?? []))
    expect(dotted?.family).toBe(6)
  })

  test('the embedded address decides the scope', () => {
    expect(scopeOf('::ffff:8.8.8.8')).toBe('global')
    expect(scopeOf('::ffff:10.0.0.1')).toBe('private')
    expect(scopeOf('::ffff:169.254.169.254')).toBe('link_local')
  })

  test('malformed IPv6 is not an address', () => {
    expect(parseAddress('::ffff:127.0.0.256')).toBeUndefined()
    expect(parseAddress('1::2::3')).toBeUndefined()
    expect(parseAddress('12345::1')).toBeUndefined()
    expect(parseAddress('1:2:3:4:5:6:7')).toBeUndefined()
  })
})

describe('6to4 and IPv4-compatible IPv6', () => {
  const cases: readonly (readonly [string, AddressScope])[] = [
    ['2002:a9fe:a9fe::', 'link_local'],
    ['2002:7f00:1::', 'loopback'],
    ['2002:0a00:0001::', 'private'],
    ['2002:e000:0001::', 'multicast'],
    ['2002:0808:0808::', 'global'],
    ['::127.0.0.1', 'loopback'],
    ['::169.254.169.254', 'link_local'],
    ['::10.0.0.1', 'private'],
    ['::8.8.8.8', 'global'],
  ]

  for (const [text, scope] of cases) {
    test(`${text} is ${scope}`, () => {
      expect(parseAddress(text)?.family).toBe(6)
      expect(scopeOf(text)).toBe(scope)
      expect(isGlobalAddress(text)).toBe(scope === 'global')
    })
  }

  test('the exact :: and ::1 addresses are matched before the IPv4-compatible form', () => {
    expect(scopeOf('::1')).toBe('loopback')
    expect(scopeOf('::')).toBe('unspecified')
  })

  test('6to4 embeds the address in bytes 2..5', () => {
    expect(Array.from(parseAddress('2002:a9fe:a9fe::')?.bytes ?? []).slice(0, 6)).toEqual([
      0x20, 0x02, 169, 254, 169, 254,
    ])
  })

  test('the metadata endpoint is not global in any embedded form', () => {
    expect(isGlobalAddress('2002:a9fe:a9fe::')).toBe(false)
    expect(isGlobalAddress('::127.0.0.1')).toBe(false)
    expect(isGlobalAddress('::ffff:169.254.169.254')).toBe(false)
  })
})

describe('classifyAddress', () => {
  test('reads bytes, not text', () => {
    expect(classifyAddress(new Uint8Array([127, 0, 0, 1]))).toBe('loopback')
    expect(classifyAddress(new Uint8Array(16))).toBe('unspecified')
  })

  test('rejects a wrong-sized buffer', () => {
    expect(() => classifyAddress(new Uint8Array(5))).toThrow(TypeError)
  })
})

test('describeAddressScope covers every scope', () => {
  const scopes: readonly AddressScope[] = [
    'global',
    'loopback',
    'private',
    'link_local',
    'multicast',
    'reserved',
    'unspecified',
  ]
  for (const scope of scopes) {
    expect(describeAddressScope(scope).length).toBeGreaterThan(0)
  }
})
