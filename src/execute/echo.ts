/**
 * Credential-echo detection. Needles are built per request from the resolved
 * components: each raw value, its percent-encoded form, the base64 Basic form,
 * and the full assembled header value. Scanning keeps the trailing
 * `maxNeedle - 1` bytes between chunks so a match straddling a chunk boundary
 * is still found.
 *
 * Scope: this catches the credential and its exact wire forms. It does not
 * catch arbitrary transformations.
 */

export interface EchoNeedles {
  readonly needles: readonly Buffer[]
  readonly maxLength: number
}

export function buildNeedles(values: Iterable<string>): EchoNeedles {
  const seen = new Set<string>()
  for (const value of values) {
    if (!value || value.length < 4) continue
    seen.add(value)
    seen.add(encodeURIComponent(value))
    seen.add(Buffer.from(value, 'utf8').toString('base64'))
  }
  const needles = [...seen]
    .filter((text) => text.length >= 4)
    .map((text) => Buffer.from(text, 'utf8'))
  return {
    needles,
    maxLength: needles.reduce((max, needle) => Math.max(max, needle.byteLength), 0),
  }
}

/** Adds the assembled wire forms a placement produces. */
export function withWireForms(values: Iterable<string>, assembled: Iterable<string>): EchoNeedles {
  return buildNeedles([...values, ...assembled])
}

export class EchoScanner {
  private tail: Buffer = Buffer.alloc(0)
  private detected = false

  constructor(private readonly needles: EchoNeedles) {}

  get found(): boolean {
    return this.detected
  }

  /** Feed one streamed chunk. Returns true once an echo has been seen. */
  push(chunk: Buffer): boolean {
    if (this.needles.needles.length === 0) return false
    const window = this.tail.byteLength === 0 ? chunk : Buffer.concat([this.tail, chunk])
    for (const needle of this.needles.needles) {
      if (window.indexOf(needle) !== -1) {
        this.detected = true
        return true
      }
    }
    const keep = Math.max(0, this.needles.maxLength - 1)
    this.tail =
      keep === 0 ? Buffer.alloc(0) : window.subarray(Math.max(0, window.byteLength - keep))
    return false
  }

  /** Scan a complete string — a header name, header value, or metadata field. */
  scanText(text: string): boolean {
    if (this.needles.needles.length === 0) return false
    const buffer = Buffer.from(text, 'utf8')
    for (const needle of this.needles.needles) {
      if (buffer.indexOf(needle) !== -1) {
        this.detected = true
        return true
      }
    }
    return false
  }
}

/** Scan every header name and value before any allowlisting is applied. */
export function scanHeaders(
  scanner: EchoScanner,
  headers: Readonly<Record<string, string | string[] | undefined>>,
): boolean {
  for (const [name, value] of Object.entries(headers)) {
    if (scanner.scanText(name)) return true
    if (typeof value === 'string' && scanner.scanText(value)) return true
    if (Array.isArray(value)) {
      for (const entry of value) if (scanner.scanText(entry)) return true
    }
  }
  return false
}
