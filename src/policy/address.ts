/**
 * IP literal parsing and scope classification. Every alternate textual form an
 * attacker can write (hex, octal, decimal integer, short dotted forms,
 * IPv4-mapped IPv6) is parsed into bytes first; classification only ever reads
 * the bytes, never the text.
 */

export type AddressScope =
  | 'global'
  | 'loopback'
  | 'private'
  | 'link_local'
  | 'multicast'
  | 'reserved'
  | 'unspecified'

export interface ParsedAddress {
  readonly family: 4 | 6
  readonly bytes: Uint8Array
  readonly scope: AddressScope
}

const HEX_PART = /^0[xX][0-9A-Fa-f]+$/
const OCTAL_PART = /^0[0-7]*$/
const DECIMAL_PART = /^[1-9][0-9]*$/
const HEX_GROUP = /^[0-9A-Fa-f]{1,4}$/

function parseIpv4Part(part: string): number | undefined {
  if (HEX_PART.test(part)) return Number.parseInt(part.slice(2), 16)
  if (OCTAL_PART.test(part)) return Number.parseInt(part, 8)
  if (DECIMAL_PART.test(part)) return Number.parseInt(part, 10)
  return undefined
}

/** inet_aton rules: leading parts are single bytes, the last part fills the remaining low bytes. */
function parseIpv4(text: string): Uint8Array | undefined {
  const parts = text.split('.')
  if (parts.length > 4) return undefined
  const values: number[] = []
  for (const part of parts) {
    const value = parseIpv4Part(part)
    if (value === undefined || !Number.isSafeInteger(value)) return undefined
    values.push(value)
  }
  const lead = values.slice(0, -1)
  for (const value of lead) {
    if (value > 0xff) return undefined
  }
  let rest = values[values.length - 1] as number
  if (rest >= 2 ** (8 * (4 - lead.length))) return undefined
  const bytes = new Uint8Array(4)
  for (let i = 0; i < lead.length; i++) bytes[i] = lead[i] as number
  for (let i = 3; i >= lead.length; i--) {
    bytes[i] = rest % 256
    rest = Math.floor(rest / 256)
  }
  return bytes
}

function parseIpv6(text: string): Uint8Array | undefined {
  let source = text
  const lastColon = source.lastIndexOf(':')
  if (lastColon < 0) return undefined
  // a trailing dotted-quad becomes the final two hex groups
  if (source.slice(lastColon + 1).includes('.')) {
    const embedded = parseIpv4(source.slice(lastColon + 1))
    if (!embedded) return undefined
    const high = (((embedded[0] as number) << 8) | (embedded[1] as number)).toString(16)
    const low = (((embedded[2] as number) << 8) | (embedded[3] as number)).toString(16)
    source = `${source.slice(0, lastColon + 1)}${high}:${low}`
  }
  const halves = source.split('::')
  if (halves.length > 2) return undefined
  const headText = halves[0] as string
  const tailText = halves.length === 2 ? (halves[1] as string) : ''
  const head = headText === '' ? [] : headText.split(':')
  const tail = tailText === '' ? [] : tailText.split(':')
  if (halves.length === 1) {
    if (head.length !== 8) return undefined
  } else if (head.length + tail.length > 7) {
    return undefined
  }
  for (const group of [...head, ...tail]) {
    if (!HEX_GROUP.test(group)) return undefined
  }
  const bytes = new Uint8Array(16)
  for (let i = 0; i < head.length; i++) {
    const value = Number.parseInt(head[i] as string, 16)
    bytes[i * 2] = value >> 8
    bytes[i * 2 + 1] = value & 0xff
  }
  for (let i = 0; i < tail.length; i++) {
    const value = Number.parseInt(tail[tail.length - 1 - i] as string, 16)
    bytes[14 - i * 2] = value >> 8
    bytes[15 - i * 2] = value & 0xff
  }
  return bytes
}

function inRange(bytes: Uint8Array, prefix: readonly number[], maskBits: number): boolean {
  const full = maskBits >> 3
  for (let i = 0; i < full; i++) {
    if (bytes[i] !== (prefix[i] ?? 0)) return false
  }
  const remainder = maskBits & 7
  if (remainder === 0) return true
  const mask = (0xff << (8 - remainder)) & 0xff
  return ((bytes[full] as number) & mask) === ((prefix[full] ?? 0) & mask)
}

function classifyIpv4(bytes: Uint8Array): AddressScope {
  if (inRange(bytes, [0], 8)) return 'unspecified'
  if (inRange(bytes, [127], 8)) return 'loopback'
  if (inRange(bytes, [10], 8)) return 'private'
  if (inRange(bytes, [172, 16], 12)) return 'private'
  if (inRange(bytes, [192, 168], 16)) return 'private'
  if (inRange(bytes, [100, 64], 10)) return 'private'
  if (inRange(bytes, [169, 254], 16)) return 'link_local'
  if (inRange(bytes, [224], 4)) return 'multicast'
  if (inRange(bytes, [240], 4)) return 'reserved'
  if (inRange(bytes, [192, 0, 0], 24)) return 'reserved'
  if (inRange(bytes, [192, 0, 2], 24)) return 'reserved'
  if (inRange(bytes, [198, 18], 15)) return 'reserved'
  if (inRange(bytes, [198, 51, 100], 24)) return 'reserved'
  if (inRange(bytes, [203, 0, 113], 24)) return 'reserved'
  return 'global'
}

function classifyIpv6(bytes: Uint8Array): AddressScope {
  if (inRange(bytes, [], 128)) return 'unspecified'
  if (inRange(bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1], 128)) return 'loopback'
  // IPv4-mapped: the embedded address decides
  if (inRange(bytes, [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff], 96)) {
    return classifyIpv4(bytes.subarray(12, 16))
  }
  // 6to4 (RFC 3056): bytes 2..5 hold the embedded address
  if (inRange(bytes, [0x20, 0x02], 16)) {
    return classifyIpv4(bytes.subarray(2, 6))
  }
  // deprecated IPv4-compatible (RFC 4291 2.5.5.1); reached only after the :: and ::1 matches above
  if (inRange(bytes, [], 96)) {
    return classifyIpv4(bytes.subarray(12, 16))
  }
  if (inRange(bytes, [0xfc], 7)) return 'private'
  if (inRange(bytes, [0xfe, 0x80], 10)) return 'link_local'
  if (inRange(bytes, [0xff], 8)) return 'multicast'
  if (inRange(bytes, [0x00, 0x64, 0xff, 0x9b], 96)) return 'reserved'
  if (inRange(bytes, [0x01, 0x00], 64)) return 'reserved'
  if (inRange(bytes, [0x20, 0x01, 0x0d, 0xb8], 32)) return 'reserved'
  if (inRange(bytes, [0x20, 0x01], 23)) return 'reserved'
  return 'global'
}

export function classifyAddress(bytes: Uint8Array): AddressScope {
  if (bytes.length === 4) return classifyIpv4(bytes)
  if (bytes.length === 16) return classifyIpv6(bytes)
  throw new TypeError(`address must be 4 or 16 bytes, got ${bytes.length}`)
}

export function parseAddress(text: string): ParsedAddress | undefined {
  if (text.length === 0) return undefined
  if (text.includes(':')) {
    const bytes = parseIpv6(text)
    return bytes ? { family: 6, bytes, scope: classifyIpv6(bytes) } : undefined
  }
  const bytes = parseIpv4(text)
  return bytes ? { family: 4, bytes, scope: classifyIpv4(bytes) } : undefined
}

export function isGlobalAddress(text: string): boolean {
  return parseAddress(text)?.scope === 'global'
}

export function describeAddressScope(scope: AddressScope): string {
  switch (scope) {
    case 'global':
      return 'globally routable address'
    case 'loopback':
      return 'loopback address'
    case 'private':
      return 'private-use address'
    case 'link_local':
      return 'link-local address'
    case 'multicast':
      return 'multicast address'
    case 'reserved':
      return 'reserved address'
    case 'unspecified':
      return 'unspecified address'
  }
}
