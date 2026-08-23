import { createHash, randomBytes } from 'node:crypto'
import { lookup as dnsLookup } from 'node:dns'
import { createWriteStream, mkdirSync, renameSync, rmSync } from 'node:fs'
import type { IncomingMessage } from 'node:http'
import { request as httpRequest } from 'node:http'
import { request as httpsRequest } from 'node:https'
import { join } from 'node:path'
import { createBrotliDecompress, createGunzip, createInflate } from 'node:zlib'
import { paths } from '../paths'
import { describeAddressScope, parseAddress } from '../policy/address'
import { LIMITS } from '../policy/limits'
import { type ValidatedTarget, validateAbsoluteUrl } from '../policy/url'
import type { ResponseMode } from '../schema/vocab'
import { type EchoScanner, scanHeaders } from './echo'

/**
 * The transport. `node:http(s)` is used rather than `fetch` because the address
 * that passed validation must structurally be the address connected to: the
 * custom `lookup` hands back only a validated address, so no second unchecked
 * resolution can happen between validation and connection.
 */

export interface TransportPolicy {
  readonly allowedOrigins: readonly string[]
  /**
   * Maintenance fetches are not pinned to a profile's origins: any global
   * https origin is in scope, and every hop is revalidated under this same
   * policy. Profile execution never sets this.
   */
  readonly allowAnyGlobalOrigin?: boolean
  readonly basePath?: string
  readonly allowNonGlobalAddresses: boolean
  readonly allowPlainHttp: boolean
  readonly maxRedirects: number
  readonly forwardCredentials: readonly { readonly from: string; readonly to: string }[]
  readonly timeoutMs: number
  readonly inlineMaxBytes: number
  readonly inlineMaxCompressedBytes: number
  readonly fileMaxBytes: number
  readonly allowedResponseHeaders: readonly string[]
}

export interface TransportRequest {
  readonly method: string
  readonly target: ValidatedTarget
  /** Caller headers plus any credential headers. Never leaves this module. */
  readonly headers: Readonly<Record<string, string>>
  readonly body?: Buffer
  readonly contentType?: string
  readonly responseMode: ResponseMode
  readonly scanner?: EchoScanner
  /** True once a credential is attached, so redirect forwarding is checked. */
  readonly credentialed: boolean
}

export type TransportFailureCode =
  | 'dns_failure'
  | 'non_global_address'
  | 'connection_failed'
  | 'tls_failure'
  | 'timeout'
  | 'redirect_outside_origins'
  | 'redirect_forwarding_not_permitted'
  | 'redirect_non_global'
  | 'redirect_limit'
  | 'redirect_missing_location'
  | 'plain_http_refused'
  | 'inline_overflow'
  | 'compressed_overflow'
  | 'file_overflow'
  | 'decode_failed'

export interface TransportSuccess {
  readonly kind: 'ok'
  readonly status: number
  /** Allowlisted response headers only. */
  readonly headers: Record<string, string>
  readonly body?: Buffer
  readonly file?: { path: string; bytes: number; hash: string; media_type: string }
  readonly bytes: number
  readonly media_type?: string
  readonly hops: string[]
}

export interface TransportFailure {
  readonly kind: 'failure'
  readonly code: TransportFailureCode
  readonly message: string
  /** True when APImanac refused by policy rather than the network failing. */
  readonly policy: boolean
}

export interface TransportEcho {
  readonly kind: 'credential_echo'
  readonly message: string
}

export type TransportResult = TransportSuccess | TransportFailure | TransportEcho

const RESPONSE_METADATA_DENYLIST = new Set([
  'set-cookie',
  'set-cookie2',
  'www-authenticate',
  'proxy-authenticate',
  'authorization',
  'proxy-authorization',
])

function failure(code: TransportFailureCode, message: string, policy: boolean): TransportFailure {
  return { kind: 'failure', code, message, policy }
}

/** Resolve once, validate every answer, and keep only what passed. */
async function resolveValidated(
  hostname: string,
  allowNonGlobal: boolean,
): Promise<{ addresses: { address: string; family: number }[] } | TransportFailure> {
  const literal = parseAddress(hostname)
  if (literal) {
    const scope = literal.scope
    if (scope !== 'global' && !allowNonGlobal) {
      return failure(
        'non_global_address',
        `${hostname} is ${describeAddressScope(scope)}; this profile does not declare that network scope`,
        true,
      )
    }
    return { addresses: [{ address: hostname, family: literal.family }] }
  }

  const answers = await new Promise<{ address: string; family: number }[] | Error>((resolve) => {
    dnsLookup(hostname, { all: true }, (error, records) => {
      if (error) resolve(error)
      else resolve(records.map((record) => ({ address: record.address, family: record.family })))
    })
  })
  if (answers instanceof Error) {
    return failure('dns_failure', `could not resolve ${hostname}`, false)
  }
  const validated: { address: string; family: number }[] = []
  for (const answer of answers) {
    // An answer that will not parse as an IP literal is refused, not assumed global.
    const parsed = parseAddress(answer.address)
    if (!parsed) continue
    if (parsed.scope === 'global' || allowNonGlobal) validated.push(answer)
  }
  if (validated.length === 0) {
    return failure(
      'non_global_address',
      `${hostname} resolves only to non-global addresses; this profile does not declare that network scope`,
      true,
    )
  }
  return { addresses: validated }
}

function decoderFor(encoding: string | undefined) {
  switch ((encoding ?? '').toLowerCase()) {
    case 'gzip':
    case 'x-gzip':
      return createGunzip()
    case 'deflate':
      return createInflate()
    case 'br':
      return createBrotliDecompress()
    default:
      return undefined
  }
}

interface ReadOutcome {
  readonly ok: boolean
  readonly code?: TransportFailureCode
  readonly message?: string
  readonly echo?: boolean
  readonly bytes: number
  readonly buffer?: Buffer
  readonly filePath?: string
  readonly hash?: string
}

/**
 * Stream the body under both the compressed and decompressed bounds, scanning
 * for a credential echo as it goes. On any bound or echo the partial temporary
 * file is removed rather than left behind.
 */
async function readBody(
  response: IncomingMessage,
  request: TransportRequest,
  policy: TransportPolicy,
): Promise<ReadOutcome> {
  const decoder = decoderFor(response.headers['content-encoding'])
  const compressedCap = policy.inlineMaxCompressedBytes
  const decompressedCap =
    request.responseMode === 'file' ? policy.fileMaxBytes : policy.inlineMaxBytes

  let temporaryPath: string | undefined
  let sink: ReturnType<typeof createWriteStream> | undefined
  if (request.responseMode === 'file') {
    const directory = paths.downloadsDir()
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    temporaryPath = join(directory, `.partial-${randomBytes(8).toString('hex')}`)
    sink = createWriteStream(temporaryPath, { mode: 0o600 })
  }

  const chunks: Buffer[] = []
  const hash = createHash('sha256')
  let compressed = 0
  let decompressed = 0
  let failureOutcome: ReadOutcome | undefined

  const cleanup = (): void => {
    sink?.destroy()
    if (temporaryPath) rmSync(temporaryPath, { force: true })
  }

  const consume = (chunk: Buffer): boolean => {
    decompressed += chunk.byteLength
    if (decompressed > decompressedCap) {
      failureOutcome = {
        ok: false,
        code: request.responseMode === 'file' ? 'file_overflow' : 'inline_overflow',
        message: `response exceeded the ${decompressedCap}-byte decompressed bound`,
        bytes: decompressed,
      }
      return false
    }
    if (request.scanner?.push(chunk)) {
      failureOutcome = { ok: false, echo: true, bytes: decompressed }
      return false
    }
    hash.update(chunk)
    if (sink) sink.write(chunk)
    else chunks.push(chunk)
    return true
  }

  await new Promise<void>((resolve) => {
    const finish = (): void => resolve()
    const abort = (): void => {
      response.destroy()
      decoder?.destroy()
      resolve()
    }

    if (decoder) {
      decoder.on('data', (chunk: Buffer) => {
        if (!consume(chunk)) abort()
      })
      decoder.on('end', finish)
      decoder.on('error', () => {
        failureOutcome = {
          ok: false,
          code: 'decode_failed',
          message: 'the response body could not be decompressed',
          bytes: decompressed,
        }
        abort()
      })
    }

    response.on('data', (chunk: Buffer) => {
      compressed += chunk.byteLength
      if (compressed > compressedCap && request.responseMode !== 'file') {
        failureOutcome = {
          ok: false,
          code: 'compressed_overflow',
          message: `response exceeded the ${compressedCap}-byte compressed bound`,
          bytes: compressed,
        }
        abort()
        return
      }
      if (decoder) decoder.write(chunk)
      else if (!consume(chunk)) abort()
    })
    response.on('end', () => {
      if (decoder) decoder.end()
      else finish()
    })
    response.on('error', () => {
      failureOutcome ??= {
        ok: false,
        code: 'connection_failed',
        message: 'the connection failed while reading the response',
        bytes: decompressed,
      }
      abort()
    })
  })

  if (failureOutcome) {
    cleanup()
    return failureOutcome
  }

  if (sink && temporaryPath) {
    await new Promise<void>((resolve) => sink.end(resolve))
    const digest = hash.digest('hex')
    const finalPath = join(paths.downloadsDir(), `${digest}.bin`)
    renameSync(temporaryPath, finalPath)
    return { ok: true, bytes: decompressed, filePath: finalPath, hash: `v1:sha256:${digest}` }
  }
  return {
    ok: true,
    bytes: decompressed,
    buffer: Buffer.concat(chunks),
    hash: `v1:sha256:${hash.digest('hex')}`,
  }
}

function allowlistHeaders(
  response: IncomingMessage,
  policy: TransportPolicy,
): Record<string, string> {
  const allowed = new Set(policy.allowedResponseHeaders.map((name) => name.toLowerCase()))
  // Content-Type and Content-Length describe the payload itself and are always safe.
  allowed.add('content-type')
  allowed.add('content-length')
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(response.headers)) {
    const lower = name.toLowerCase()
    if (RESPONSE_METADATA_DENYLIST.has(lower)) continue
    if (!allowed.has(lower)) continue
    if (typeof value === 'string') out[lower] = value
  }
  return out
}

function originOf(url: string): string {
  return new URL(url).origin
}

/** Origin of a redirect target, or a sentinel that no allowlist will match. */
function safeOrigin(url: string): string {
  try {
    const parsed = new URL(url)
    return parsed.protocol === 'https:' || parsed.protocol === 'http:'
      ? parsed.origin
      : 'about:invalid'
  } catch {
    return 'about:invalid'
  }
}

/** Path plus canonically encoded query, as the request line carries it. */
function requestPath(target: ValidatedTarget): string {
  const mark = target.url.indexOf('?')
  return mark === -1 ? target.path : `${target.path}${target.url.slice(mark)}`
}

/** Send one request, following redirects manually and revalidating each hop. */
export async function send(
  request: TransportRequest,
  policy: TransportPolicy,
): Promise<TransportResult> {
  let target = request.target
  const credentialed = request.credentialed
  const hops: string[] = []

  for (let hop = 0; hop <= policy.maxRedirects; hop++) {
    if (target.scheme === 'http:' && !policy.allowPlainHttp) {
      return failure(
        'plain_http_refused',
        `${target.origin} is plain HTTP, which this policy refuses`,
        true,
      )
    }

    const resolved = await resolveValidated(target.hostname, policy.allowNonGlobalAddresses)
    if ('kind' in resolved) return resolved
    const validated = resolved.addresses

    const attempt = await new Promise<{ response: IncomingMessage } | TransportFailure>(
      (resolve) => {
        const send = target.scheme === 'https:' ? httpsRequest : httpRequest
        const headers: Record<string, string> = { ...request.headers }
        if (request.body) {
          headers['content-length'] = String(request.body.byteLength)
          if (request.contentType) headers['content-type'] = request.contentType
        }
        headers.host =
          target.port === (target.scheme === 'https:' ? 443 : 80)
            ? target.hostname
            : `${target.hostname}:${target.port}`
        headers['accept-encoding'] = 'gzip, deflate, br'

        const outbound = send(
          {
            method: request.method,
            protocol: target.scheme,
            hostname: target.hostname,
            port: target.port,
            path: requestPath(target),
            headers,
            servername: target.scheme === 'https:' ? target.hostname : undefined,
            timeout: policy.timeoutMs,
            // Only an address that already passed validation is ever handed back.
            lookup: (_hostname, options, callback) => {
              const wanted = typeof options === 'object' && options ? options.family : undefined
              const pick =
                validated.find((entry) => !wanted || wanted === 0 || entry.family === wanted) ??
                validated[0]
              if (!pick) {
                ;(callback as (error: Error | null) => void)(new Error('no validated address'))
                return
              }
              if (typeof options === 'object' && options && options.all) {
                ;(callback as unknown as (e: Error | null, a: unknown) => void)(null, [
                  { address: pick.address, family: pick.family },
                ])
                return
              }
              ;(callback as unknown as (e: Error | null, a: string, f: number) => void)(
                null,
                pick.address,
                pick.family,
              )
            },
          },
          (response) => resolve({ response }),
        )
        outbound.on('timeout', () => {
          outbound.destroy()
          resolve(failure('timeout', `the request exceeded the ${policy.timeoutMs}ms bound`, false))
        })
        outbound.on('error', (error: NodeJS.ErrnoException) => {
          const tls = /certificate|SSL|TLS|ERR_TLS/i.test(error.message)
          resolve(
            failure(
              tls ? 'tls_failure' : 'connection_failed',
              `the connection to ${target.origin} failed`,
              false,
            ),
          )
        })
        if (request.body) outbound.write(request.body)
        outbound.end()
      },
    )

    if ('kind' in attempt) return attempt
    const response = attempt.response
    const status = response.statusCode ?? 0

    if (status >= 300 && status < 400 && status !== 304) {
      response.resume()
      const location = response.headers.location
      if (!location) {
        return failure('redirect_missing_location', `${status} carried no Location header`, false)
      }
      if (hop === policy.maxRedirects) {
        return failure(
          'redirect_limit',
          `the redirect chain exceeded the ${policy.maxRedirects}-hop bound`,
          true,
        )
      }
      const absolute = new URL(location, target.url).toString()
      // The remote chose this target, so it is revalidated in full.
      const revalidated = validateAbsoluteUrl(
        absolute,
        policy.allowAnyGlobalOrigin ? [safeOrigin(absolute)] : policy.allowedOrigins,
        policy.allowAnyGlobalOrigin ? undefined : policy.basePath,
      )
      if (!revalidated.ok) {
        return failure(
          'redirect_outside_origins',
          `${target.origin} redirected to ${originOf(absolute)}, which is not one of this profile's allowed origins; the redirect was not followed`,
          true,
        )
      }
      const nextOrigin = revalidated.target.origin
      if (credentialed && nextOrigin !== target.origin) {
        const permitted = policy.forwardCredentials.some(
          (pair) => pair.from === target.origin && pair.to === nextOrigin,
        )
        if (!permitted) {
          return failure(
            'redirect_forwarding_not_permitted',
            `${target.origin} redirected to ${nextOrigin}, and this profile does not permit forwarding the credential for that pair; the redirect was not followed`,
            true,
          )
        }
      }
      const nextAddress = await resolveValidated(
        revalidated.target.hostname,
        policy.allowNonGlobalAddresses,
      )
      if ('kind' in nextAddress) {
        return failure(
          'redirect_non_global',
          `${nextOrigin} resolves outside this profile's network scope; the redirect was not followed`,
          true,
        )
      }
      hops.push(nextOrigin + revalidated.target.path)
      target = revalidated.target
      continue
    }

    if (request.scanner && scanHeaders(request.scanner, response.headers)) {
      response.destroy()
      return { kind: 'credential_echo', message: 'the response echoed the credential in a header' }
    }

    const outcome = await readBody(response, request, policy)
    if (outcome.echo) {
      return { kind: 'credential_echo', message: 'the response echoed the credential in its body' }
    }
    if (!outcome.ok) {
      return failure(
        outcome.code ?? 'connection_failed',
        outcome.message ?? 'the response could not be read',
        outcome.code === 'inline_overflow' ||
          outcome.code === 'compressed_overflow' ||
          outcome.code === 'file_overflow',
      )
    }

    const headers = allowlistHeaders(response, policy)
    if (request.scanner) {
      for (const [name, value] of Object.entries(headers)) {
        if (request.scanner.scanText(name) || request.scanner.scanText(value)) {
          if (outcome.filePath) rmSync(outcome.filePath, { force: true })
          return {
            kind: 'credential_echo',
            message: 'the response echoed the credential in returned metadata',
          }
        }
      }
    }

    return {
      kind: 'ok',
      status,
      headers,
      body: outcome.buffer,
      file: outcome.filePath
        ? {
            path: outcome.filePath,
            bytes: outcome.bytes,
            hash: outcome.hash as string,
            media_type: headers['content-type'] ?? 'application/octet-stream',
          }
        : undefined,
      bytes: outcome.bytes,
      media_type: headers['content-type'],
      hops,
    }
  }

  return failure(
    'redirect_limit',
    `the redirect chain exceeded the ${policy.maxRedirects}-hop bound`,
    true,
  )
}

export const DEFAULT_TIMEOUT_MS = LIMITS.requestTimeoutMs
