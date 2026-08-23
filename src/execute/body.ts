import { createHash } from 'node:crypto'
import { ApimanacError } from '../errors'
import { LIMITS } from '../policy/limits'

/**
 * v0 request bodies: none, JSON, text, or URL-encoded form. Multipart and
 * streaming uploads are refused as unsupported, and an oversized body is
 * refused before any connection is opened.
 */

export type BodyInput =
  | { kind: 'none' }
  | { kind: 'json'; value: unknown }
  | { kind: 'text'; value: string; content_type?: string }
  | { kind: 'form'; value: Readonly<Record<string, string>> }

export interface EncodedBody {
  readonly bytes: Buffer
  readonly contentType: string
  readonly hash: string
}

const CONTENT_TYPES = {
  json: 'application/json',
  text: 'text/plain; charset=utf-8',
  form: 'application/x-www-form-urlencoded',
} as const

export function encodeBody(
  input: BodyInput | undefined,
  maxBytes = LIMITS.requestBodyMaxBytes,
): EncodedBody | undefined {
  if (!input || input.kind === 'none') return undefined
  let bytes: Buffer
  let contentType: string
  switch (input.kind) {
    case 'json':
      bytes = Buffer.from(JSON.stringify(input.value ?? null), 'utf8')
      contentType = CONTENT_TYPES.json
      break
    case 'text':
      bytes = Buffer.from(input.value, 'utf8')
      contentType = input.content_type ?? CONTENT_TYPES.text
      break
    case 'form': {
      const params = new URLSearchParams()
      for (const [name, value] of Object.entries(input.value)) params.append(name, value)
      bytes = Buffer.from(params.toString(), 'utf8')
      contentType = CONTENT_TYPES.form
      break
    }
  }
  if (bytes.byteLength > maxBytes) {
    throw new ApimanacError(
      'unsupported_request',
      `request body is ${bytes.byteLength} bytes, over the ${maxBytes}-byte bound`,
      { bytes: bytes.byteLength, bound: maxBytes },
    )
  }
  return {
    bytes,
    contentType,
    hash: `v1:sha256:${createHash('sha256').update(bytes).digest('hex')}`,
  }
}

const UNSUPPORTED_KINDS = new Set(['multipart', 'stream', 'file', 'binary', 'websocket', 'grpc'])

/** Refuse the body shapes v0 does not carry, before anything else runs. */
export function assertSupportedBody(kind: string | undefined): void {
  if (kind && UNSUPPORTED_KINDS.has(kind)) {
    throw new ApimanacError(
      'unsupported_request',
      `\`${kind}\` request bodies are not supported in this version`,
      { kind },
    )
  }
}

/** Hash used wherever a body hash is required, including for an absent body. */
export const EMPTY_BODY_HASH = `v1:sha256:${createHash('sha256').update(Buffer.alloc(0)).digest('hex')}`
