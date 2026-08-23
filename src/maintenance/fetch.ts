import { MAINTENANCE_POLICY } from '../policy/maintenance'
import { validateAbsoluteUrl } from '../policy/url'
import { send, type TransportPolicy } from '../execute/transport'

/**
 * Maintenance fetches run under the fixed policy in `src/policy/maintenance.ts`:
 * https only, global addresses only, no credential of any kind, bounded
 * redirects revalidated under the same policy, bounded size and time. No
 * execution profile widens it.
 */

export interface FetchOutcome {
  readonly ok: boolean
  readonly status?: number
  readonly bytes?: Buffer
  readonly mediaType?: string
  readonly url: string
  readonly retrievedAt: string
  readonly message?: string
  /** True when the fixed maintenance policy refused, not the network. */
  readonly refused?: boolean
}

function policyFor(origin: string): TransportPolicy {
  return {
    allowedOrigins: [origin],
    allowAnyGlobalOrigin: true,
    allowNonGlobalAddresses: MAINTENANCE_POLICY.allowNonGlobalAddresses,
    allowPlainHttp: MAINTENANCE_POLICY.allowPlainHttp,
    maxRedirects: MAINTENANCE_POLICY.maxRedirects,
    forwardCredentials: [],
    timeoutMs: MAINTENANCE_POLICY.timeoutMs,
    inlineMaxBytes: MAINTENANCE_POLICY.maxResponseBytes,
    inlineMaxCompressedBytes: MAINTENANCE_POLICY.maxResponseBytes,
    fileMaxBytes: MAINTENANCE_POLICY.maxResponseBytes,
    allowedResponseHeaders: [],
  }
}

export async function maintenanceFetch(url: string): Promise<FetchOutcome> {
  const retrievedAt = new Date().toISOString()
  let parsed: URL
  try {
    parsed = new URL(url)
  } catch {
    return {
      ok: false,
      url,
      retrievedAt,
      refused: true,
      message: `\`${url}\` is not an absolute URL`,
    }
  }
  if (parsed.protocol !== 'https:') {
    return {
      ok: false,
      url,
      retrievedAt,
      refused: true,
      message: `the fixed maintenance policy is HTTPS only; \`${url}\` was refused`,
    }
  }
  const target = validateAbsoluteUrl(url, [parsed.origin])
  if (!target.ok) {
    return {
      ok: false,
      url,
      retrievedAt,
      refused: true,
      message: `${target.rejection.code}: ${target.rejection.message}`,
    }
  }

  const result = await send(
    {
      method: 'GET',
      target: target.target,
      // No credential of any kind is attached to a maintenance fetch.
      headers: { accept: 'application/json, application/yaml, text/html;q=0.8, */*;q=0.5' },
      responseMode: 'inline',
      credentialed: false,
    },
    policyFor(parsed.origin),
  )

  if (result.kind === 'credential_echo') {
    return { ok: false, url, retrievedAt, refused: true, message: result.message }
  }
  if (result.kind === 'failure') {
    return { ok: false, url, retrievedAt, refused: result.policy, message: result.message }
  }
  return {
    ok: result.status >= 200 && result.status < 300,
    status: result.status,
    bytes: result.body,
    mediaType: result.headers['content-type'],
    url,
    retrievedAt,
    message: result.status >= 300 ? `the remote returned ${result.status}` : undefined,
  }
}

/**
 * The optional external extractor. Unconfigured by default: with no provider,
 * `add` reports that local extraction failed and writes nothing.
 */
export interface ExternalExtractor {
  readonly name: string
  extract(url: string): Promise<{ name?: string; description?: string } | undefined>
}

let extractor: ExternalExtractor | undefined

export function configureExternalExtractor(provider: ExternalExtractor | undefined): void {
  extractor = provider
}

export function externalExtractor(): ExternalExtractor | undefined {
  return extractor
}
