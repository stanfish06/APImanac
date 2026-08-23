import { createHash } from 'node:crypto'
import type { GrantStore } from '../auth/grants'
import type { CatalogRoot } from '../catalog/root'
import {
  committedProfilesFor,
  evaluateEligibility,
  resolveCommittedIdentity,
  type Eligibility,
  type EligibleProfile,
} from '../policy/eligibility'
import { LIMITS } from '../policy/limits'
import { evaluatePermission } from '../policy/permissions'
import { checkCallerFields } from '../policy/reserved'
import { validateTarget } from '../policy/url'
import type { ExecutionProfile } from '../schema/execution'
import { templatePlaceholders } from '../schema/execution'
import type { PermissionDecision, ResponseMode } from '../schema/vocab'
import { EMPTY_BODY_HASH, type BodyInput, assertSupportedBody, encodeBody } from './body'
import { ResponseCache } from './cache'
import { type ApprovalTokens, type ConfirmationChannel, confirmRequest } from './confirm'
import { EchoScanner, buildNeedles } from './echo'
import type { HealthStore } from './health'
import type { SanitizedRequest } from './sanitize'
import { previewOf } from './sanitize'
import { type TransportPolicy, send } from './transport'

/**
 * The call orchestrator. Ordering is load bearing: a denied operation, an
 * ineligible profile, and an unsupported auth type all refuse before any
 * credential is resolved and before any packet leaves the process.
 */

export type CallOutcomeKind =
  | 'success'
  | 'remote_response'
  | 'ineligible'
  | 'denied'
  | 'confirmation_required'
  | 'confirmation_declined'
  | 'missing_grant'
  | 'missing_credential'
  | 'unsupported_auth'
  | 'unsupported_request'
  | 'ambiguous_profile'
  | 'ambiguous_account'
  | 'policy_failure'
  | 'network_failure'
  | 'credential_echo_detected'
  | 'not_found'

export interface ProfileCandidate {
  readonly profile_id: string
  readonly file: string
  readonly eligible: boolean
  readonly reason?: string
}

export interface CallOutcome {
  readonly kind: CallOutcomeKind
  readonly message: string
  /** Present once a target has been validated; built only from sanitized data. */
  readonly request?: SanitizedRequest
  readonly api_id?: string
  readonly profile_id?: string
  readonly decision?: PermissionDecision
  readonly status?: number
  readonly headers?: Record<string, string>
  readonly body?: string
  readonly body_encoding?: 'utf-8' | 'base64'
  readonly file?: { path: string; bytes: number; hash: string; media_type: string }
  readonly bytes?: number
  readonly truncated?: false
  readonly from_cache?: boolean
  readonly candidates?: string[]
  readonly profiles?: ProfileCandidate[]
  readonly missing_components?: string[]
  readonly preview?: string
  /** Remote bytes are untrusted content, never an APImanac message. */
  readonly remote_content?: boolean
  readonly resolved_alias?: string
  readonly redirected_from?: string
}

export interface CallRequest {
  readonly root: CatalogRoot
  readonly api: string
  readonly profile?: string
  readonly account?: string
  readonly method: string
  readonly path: string
  readonly query?: Readonly<Record<string, string>>
  readonly headers?: Readonly<Record<string, string>>
  readonly body?: BodyInput
  readonly bodyKind?: string
  readonly responseMode?: ResponseMode
  readonly origin?: string
}

export interface CallServices {
  readonly grants: GrantStore
  readonly tokens: ApprovalTokens
  readonly health?: HealthStore
  readonly cache?: ResponseCache
  /** Absent means no confirmation is possible in this context. */
  readonly channel?: ConfirmationChannel
  /** Names the interactive path a caller should use when confirmation is impossible. */
  readonly confirmationHint?: string
}

function redirectPolicyHash(profile: ExecutionProfile): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        max: profile.redirects.max,
        forward: [...profile.redirects.forward_credentials].sort((a, b) =>
          `${a.from}>${a.to}` < `${b.from}>${b.to}` ? -1 : 1,
        ),
      }),
    )
    .digest('hex')
}

export function transportPolicyFor(profile: ExecutionProfile): TransportPolicy {
  return {
    allowedOrigins: profile.origins,
    basePath: profile.base_path,
    allowNonGlobalAddresses: profile.network_scope === 'private',
    allowPlainHttp: profile.origins.some((origin) => origin.startsWith('http://')),
    maxRedirects: profile.redirects.max,
    forwardCredentials: profile.redirects.forward_credentials,
    timeoutMs: profile.response.timeout_ms ?? LIMITS.requestTimeoutMs,
    inlineMaxBytes: profile.response.inline_max_bytes ?? LIMITS.inlineMaxBytes,
    inlineMaxCompressedBytes:
      profile.response.inline_max_compressed_bytes ?? LIMITS.inlineMaxCompressedBytes,
    fileMaxBytes: profile.response.file_max_bytes ?? LIMITS.fileMaxBytes,
    allowedResponseHeaders: profile.response.allowed_headers,
  }
}

interface AppliedCredential {
  readonly headers: Record<string, string>
  readonly query: [string, string][]
  readonly needles: string[]
  readonly credentialQueryValues: string[]
}

/** Substitute declared component names into a placement template. */
function fill(template: string, components: ReadonlyMap<string, string>): string {
  let out = template
  for (const placeholder of templatePlaceholders(template)) {
    out = out.replace(`{${placeholder}}`, components.get(placeholder) ?? '')
  }
  return out
}

function applyCredential(
  profile: ExecutionProfile,
  components: ReadonlyMap<string, string>,
): AppliedCredential {
  const headers: Record<string, string> = {}
  const query: [string, string][] = []
  const needles = [...components.values()]
  const credentialQueryValues: string[] = []
  for (const placement of profile.auth.placements) {
    if (placement.kind === 'basic') {
      const pair = `${components.get(placement.username) ?? ''}:${components.get(placement.password) ?? ''}`
      const wire = `Basic ${Buffer.from(pair, 'utf8').toString('base64')}`
      headers[placement.header] = wire
      needles.push(pair, wire)
      continue
    }
    const value = fill(placement.template, components)
    if (placement.kind === 'header') {
      headers[placement.header] = value
      needles.push(value)
    } else {
      query.push([placement.parameter, value])
      needles.push(value)
      credentialQueryValues.push(value)
    }
  }
  return { headers, query, needles, credentialQueryValues }
}

function selectProfile(
  request: CallRequest,
  services: CallServices,
  apiId: string,
): { chosen: EligibleProfile; profileId: string } | CallOutcome {
  const ids = request.profile ? [request.profile] : committedProfilesFor(request.root, apiId)
  if (ids.length === 0) {
    return {
      kind: 'ineligible',
      api_id: apiId,
      message: `no committed execution profile exists for \`${apiId}\``,
      profiles: [],
    }
  }

  const evaluated = ids.map((profileId) => ({
    profileId,
    eligibility: evaluateEligibility(request.root, apiId, profileId),
  }))

  if (request.profile) {
    const only = evaluated[0]
    if (!only) {
      return { kind: 'not_found', message: `no profile \`${request.profile}\` for \`${apiId}\`` }
    }
    if (!only.eligibility.eligible) {
      return ineligibleOutcome(apiId, [only])
    }
    return { chosen: only.eligibility, profileId: only.profileId }
  }

  // Automatic selection considers only committed, eligible profiles that are
  // also paired with a ready grant when authentication is required.
  const usable = evaluated.filter((entry) => {
    if (!entry.eligibility.eligible) return false
    const profile = entry.eligibility.profile
    if (profile.auth.type === 'none') return true
    const readiness = services.grants.readinessFor(
      profile,
      entry.eligibility.authorityFingerprint,
      request.account,
    )
    return readiness.readiness === 'ready'
  })

  const sole = usable[0]
  if (usable.length === 1 && sole?.eligibility.eligible) {
    return { chosen: sole.eligibility, profileId: sole.profileId }
  }
  if (usable.length > 1) {
    return {
      kind: 'ambiguous_profile',
      api_id: apiId,
      message: `several eligible profiles exist for \`${apiId}\`; name one with --profile`,
      candidates: usable.map((entry) => entry.profileId),
      profiles: describeCandidates(evaluated),
    }
  }
  return ineligibleOutcome(apiId, evaluated)
}

function describeCandidates(
  evaluated: { profileId: string; eligibility: Eligibility }[],
): ProfileCandidate[] {
  return evaluated.map((entry) => ({
    profile_id: entry.profileId,
    file: entry.eligibility.file,
    eligible: entry.eligibility.eligible,
    reason: entry.eligibility.eligible ? undefined : entry.eligibility.reason,
  }))
}

function ineligibleOutcome(
  apiId: string,
  evaluated: { profileId: string; eligibility: Eligibility }[],
): CallOutcome {
  const candidateOnly = evaluated.find(
    (entry) => !entry.eligibility.eligible && entry.eligibility.code === 'candidate',
  )
  const unsupported = evaluated.find(
    (entry) => !entry.eligibility.eligible && entry.eligibility.code === 'unsupported_auth',
  )
  const profiles = describeCandidates(evaluated)
  if (unsupported && !unsupported.eligibility.eligible) {
    return {
      kind: 'unsupported_auth',
      api_id: apiId,
      profile_id: unsupported.profileId,
      message: unsupported.eligibility.reason,
      profiles,
    }
  }
  if (candidateOnly && !candidateOnly.eligibility.eligible) {
    return {
      kind: 'ineligible',
      api_id: apiId,
      profile_id: candidateOnly.profileId,
      message: candidateOnly.eligibility.reason,
      profiles,
    }
  }
  const first = evaluated[0]
  return {
    kind: 'ineligible',
    api_id: apiId,
    profile_id: first?.profileId,
    message:
      first && !first.eligibility.eligible
        ? first.eligibility.reason
        : `no eligible execution profile for \`${apiId}\``,
    profiles,
  }
}

export async function callApi(request: CallRequest, services: CallServices): Promise<CallOutcome> {
  const identity = resolveCommittedIdentity(request.root, request.api)
  if (!identity) {
    return {
      kind: 'not_found',
      message: `\`${request.api}\` is not a committed canonical id or alias in this catalog`,
    }
  }
  const apiId = identity.id

  const selection = selectProfile(request, services, apiId)
  if ('kind' in selection) {
    return {
      ...selection,
      resolved_alias: identity.viaAlias,
      redirected_from: identity.viaMerge?.[0],
    }
  }
  const { chosen, profileId } = selection
  const profile = chosen.profile

  try {
    assertSupportedBody(request.bodyKind)
  } catch (error) {
    return {
      kind: 'unsupported_request',
      api_id: apiId,
      profile_id: profileId,
      message: (error as Error).message,
    }
  }

  const reserved = checkCallerFields(profile, request.headers, request.query)
  if (reserved) {
    return {
      kind: 'policy_failure',
      api_id: apiId,
      profile_id: profileId,
      message: reserved.message,
    }
  }

  const validated = validateTarget({
    path: request.path,
    origin: request.origin,
    query: request.query,
    allowedOrigins: profile.origins,
    basePath: profile.base_path,
  })
  if (!validated.ok) {
    return {
      kind: 'policy_failure',
      api_id: apiId,
      profile_id: profileId,
      message: `${validated.rejection.code}: ${validated.rejection.message}${validated.rejection.normalized ? ` (normalized: ${validated.rejection.normalized})` : ''}`,
    }
  }
  const target = validated.target

  let encoded: ReturnType<typeof encodeBody>
  try {
    encoded = encodeBody(request.body, LIMITS.requestBodyMaxBytes)
  } catch (error) {
    return {
      kind: 'unsupported_request',
      api_id: apiId,
      profile_id: profileId,
      message: (error as Error).message,
    }
  }

  const method = request.method.toUpperCase()
  const permission = evaluatePermission(profile, method, target.path)
  if (permission.decision === 'deny') {
    // No credential is resolved and no request is sent.
    return {
      kind: 'denied',
      api_id: apiId,
      profile_id: profileId,
      decision: 'deny',
      message: permission.reason,
    }
  }

  const readiness = services.grants.readinessFor(
    profile,
    chosen.authorityFingerprint,
    request.account,
  )
  if (readiness.readiness === 'unsupported_auth') {
    return {
      kind: 'unsupported_auth',
      api_id: apiId,
      profile_id: profileId,
      message: readiness.message,
    }
  }
  if (readiness.readiness === 'no_grant') {
    return {
      kind: 'missing_grant',
      api_id: apiId,
      profile_id: profileId,
      message: readiness.message,
      missing_components: readiness.requiredComponents,
    }
  }
  if (readiness.readiness === 'fingerprint_mismatch') {
    return {
      kind: 'missing_grant',
      api_id: apiId,
      profile_id: profileId,
      message: readiness.message,
    }
  }
  const account = services.grants.selectAccount(readiness, request.account)
  if (!account.ok) {
    return {
      kind: account.readiness === 'ambiguous_account' ? 'ambiguous_account' : 'missing_credential',
      api_id: apiId,
      profile_id: profileId,
      message: account.message,
      candidates: account.candidates,
      missing_components: readiness.requiredComponents,
    }
  }

  const responseMode: ResponseMode = request.responseMode ?? 'inline'
  const sanitized: SanitizedRequest = {
    api_id: apiId,
    profile_id: profileId,
    account: account.account?.name,
    method,
    origin: target.origin,
    path: target.path,
    query: target.query,
    header_names: Object.keys(request.headers ?? {}).sort(),
    body: encoded
      ? { content_type: encoded.contentType, bytes: encoded.bytes.byteLength, hash: encoded.hash }
      : undefined,
    response_mode: responseMode,
    redirect_policy_hash: redirectPolicyHash(profile),
  }

  if (permission.decision === 'confirm') {
    if (!services.channel) {
      return {
        kind: 'confirmation_required',
        api_id: apiId,
        profile_id: profileId,
        decision: 'confirm',
        request: sanitized,
        preview: previewOf(sanitized).summary,
        message:
          services.confirmationHint ??
          'this operation requires an interactive confirmation; run `apimanac call` on a controlling terminal',
      }
    }
    const outcome = await confirmRequest(services.channel, services.tokens, sanitized)
    if (!outcome.accepted) {
      return {
        kind: 'confirmation_declined',
        api_id: apiId,
        profile_id: profileId,
        decision: 'confirm',
        request: sanitized,
        message: 'confirmation was declined; no request was sent',
      }
    }
    const check = services.tokens.consume(outcome.token, sanitized)
    if (!check.ok) {
      return {
        kind: 'confirmation_required',
        api_id: apiId,
        profile_id: profileId,
        decision: 'confirm',
        request: sanitized,
        message: check.message,
      }
    }
  }

  let components = new Map<string, string>()
  if (account.account) {
    try {
      components = services.grants.resolveComponents(
        profile,
        chosen.authorityFingerprint,
        account.account.name,
      )
    } catch (error) {
      const failure = error as { kind?: string; message: string; detail?: { component?: string } }
      return {
        kind: failure.kind === 'missing_grant' ? 'missing_grant' : 'missing_credential',
        api_id: apiId,
        profile_id: profileId,
        message: failure.message,
        missing_components: failure.detail?.component ? [failure.detail.component] : undefined,
      }
    }
  }
  const credential = applyCredential(profile, components)
  const scanner = credential.needles.length
    ? new EchoScanner(buildNeedles(credential.needles))
    : undefined

  const cacheKey = services.cache
    ? services.cache.identity(
        sanitized,
        chosen.contractHash,
        credential.credentialQueryValues,
        representationHeaders(request.headers),
      )
    : undefined
  const cacheable =
    profile.cache.enabled && ResponseCache.cacheable(method, profile.cache.allow_mutations)
  if (services.cache && cacheKey && cacheable) {
    const hit = services.cache.read(cacheKey)
    if (hit) {
      return successOutcome(sanitized, hit.status, hit.headers, hit.body, undefined, true)
    }
  }

  const authenticatedQuery: [string, string][] = [
    ...target.query.map(([name, value]) => [name, value] as [string, string]),
    ...credential.query,
  ]
  const authenticatedTarget = {
    ...target,
    query: authenticatedQuery,
    url: `${target.origin}${target.path}${
      authenticatedQuery.length
        ? `?${authenticatedQuery.map(([n, v]) => `${encodeURIComponent(n)}=${encodeURIComponent(v)}`).join('&')}`
        : ''
    }`,
  }

  const result = await send(
    {
      method,
      target: authenticatedTarget,
      headers: { ...lowercaseKeys(request.headers ?? {}), ...credential.headers },
      body: encoded?.bytes,
      contentType: encoded?.contentType,
      responseMode,
      scanner,
      credentialed: credential.needles.length > 0,
    },
    transportPolicyFor(profile),
  )

  if (result.kind === 'credential_echo') {
    services.health?.record(apiId, profileId, { status: undefined })
    return {
      kind: 'credential_echo_detected',
      api_id: apiId,
      profile_id: profileId,
      request: sanitized,
      message: result.message,
    }
  }

  if (result.kind === 'failure') {
    services.health?.record(apiId, profileId, {
      transportFailure: transportFailureKind(result.code),
      redirectRefused: result.code.startsWith('redirect_'),
    })
    return {
      kind: result.policy ? 'policy_failure' : 'network_failure',
      api_id: apiId,
      profile_id: profileId,
      request: sanitized,
      message: result.message,
    }
  }

  services.health?.record(apiId, profileId, {
    status: result.status,
    retryAfter: Boolean(result.headers['retry-after']),
  })

  if (services.cache && cacheKey && cacheable && result.body && result.status < 400) {
    services.cache.write(
      cacheKey,
      sanitized,
      { status: result.status, headers: result.headers, body: result.body },
      profile.cache.ttl_seconds,
    )
  }

  return successOutcome(sanitized, result.status, result.headers, result.body, result.file, false)
}

function transportFailureKind(code: string): 'dns' | 'connection' | 'tls' | 'timeout' | undefined {
  if (code === 'dns_failure') return 'dns'
  if (code === 'connection_failed') return 'connection'
  if (code === 'tls_failure') return 'tls'
  if (code === 'timeout') return 'timeout'
  return undefined
}

/** Caller headers that change which representation the remote returns. */
const REPRESENTATION_HEADERS = new Set(['accept', 'accept-language', 'accept-encoding'])

function representationHeaders(
  headers: Readonly<Record<string, string>> | undefined,
): [string, string][] {
  if (!headers) return []
  return Object.entries(headers)
    .filter(([name]) => REPRESENTATION_HEADERS.has(name.toLowerCase()))
    .map(([name, value]) => [name.toLowerCase(), value] as [string, string])
    .sort(([a], [b]) => (a < b ? -1 : 1))
}

function lowercaseKeys(headers: Readonly<Record<string, string>>): Record<string, string> {
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(headers)) out[name.toLowerCase()] = value
  return out
}

function successOutcome(
  request: SanitizedRequest,
  status: number,
  headers: Record<string, string>,
  body: Buffer | undefined,
  file: { path: string; bytes: number; hash: string; media_type: string } | undefined,
  fromCache: boolean,
): CallOutcome {
  const textual = /json|text|xml|javascript|yaml|urlencoded/i.test(headers['content-type'] ?? '')
  return {
    kind: status >= 400 ? 'remote_response' : 'success',
    api_id: request.api_id,
    profile_id: request.profile_id,
    request,
    status,
    headers,
    body: body ? (textual ? body.toString('utf8') : body.toString('base64')) : undefined,
    body_encoding: body ? (textual ? 'utf-8' : 'base64') : undefined,
    file,
    bytes: body?.byteLength ?? file?.bytes ?? 0,
    from_cache: fromCache,
    remote_content: true,
    message:
      status >= 400
        ? `the remote returned ${status}; this is remote content, not an APImanac refusal`
        : `${status}`,
  }
}

export { EMPTY_BODY_HASH }
