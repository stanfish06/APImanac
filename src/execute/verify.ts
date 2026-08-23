import { createHash } from 'node:crypto'
import { existsSync, readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse, stringify } from 'yaml'
import type { GrantStore } from '../auth/grants'
import { authorityFingerprint, contractHash } from '../catalog/canonical'
import { profilePath } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import { LIMITS } from '../policy/limits'
import { validateTarget } from '../policy/url'
import { ExecutionProfile } from '../schema/execution'
import { isExecutableAuthType } from '../schema/vocab'
import { transportPolicyFor } from './call'
import type { ConfirmationChannel } from './confirm'
import { buildNeedles, EchoScanner } from './echo'
import type { HealthStore } from './health'
import { previewOf, type SanitizedRequest } from './sanitize'
import { send } from './transport'

/**
 * `verify` is the only path from `candidate` to `verified`. Every check reads
 * the worktree candidate file rather than the committed snapshot, so a profile
 * that has never been committed can be verified — and stays ineligible for
 * ordinary execution the whole time.
 */

export const TOOL_VERSION = '0.0.0'

export type VerifyOutcomeKind =
  | 'verified'
  | 'not_found'
  | 'invalid'
  | 'no_terminal'
  | 'declined'
  | 'missing_grant'
  | 'missing_credential'
  | 'unsupported_auth'
  | 'no_probe'
  | 'probe_failed'
  | 'credential_echo_detected'

export interface VerifyOutcome {
  readonly kind: VerifyOutcomeKind
  readonly message: string
  readonly file?: string
  readonly api_id?: string
  readonly profile_id?: string
  readonly contract_hash?: string
  readonly authority_fingerprint?: string
  readonly status?: number
  readonly request?: SanitizedRequest
  /** True when the evidence was written as an uncommitted worktree change. */
  readonly evidence_written?: boolean
}

export interface VerifyRequest {
  readonly root: CatalogRoot
  readonly api: string
  readonly profile: string
  readonly account?: string
}

export interface VerifyServices {
  readonly grants: GrantStore
  /** Verification always confirms interactively; without a channel it refuses. */
  readonly channel?: ConfirmationChannel
  readonly health?: HealthStore
  readonly now?: () => Date
}

export async function verifyProfile(
  request: VerifyRequest,
  services: VerifyServices,
): Promise<VerifyOutcome> {
  const file = profilePath(request.api, request.profile)
  const absolute = join(request.root.path, file)
  if (!existsSync(absolute)) {
    return { kind: 'not_found', file, message: `${file} does not exist in the worktree` }
  }

  // Schema validation, then origin, auth-shape, and permission-policy checks —
  // all before any probe is sent.
  const text = readFileSync(absolute, 'utf8')
  let document: unknown
  try {
    document = parse(text)
  } catch (error) {
    return {
      kind: 'invalid',
      file,
      message: `${file} is not valid YAML: ${(error as Error).message}`,
    }
  }
  const parsed = ExecutionProfile.safeParse(document)
  if (!parsed.success) {
    return {
      kind: 'invalid',
      file,
      message: `${file} does not validate: ${parsed.error.issues
        .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
        .join('; ')}`,
    }
  }
  const candidate = parsed.data
  if (candidate.api_id !== request.api || candidate.profile_id !== request.profile) {
    return {
      kind: 'invalid',
      file,
      message: `${file} declares ${candidate.api_id}/${candidate.profile_id}`,
    }
  }
  if (!isExecutableAuthType(candidate.auth.type)) {
    return {
      kind: 'unsupported_auth',
      file,
      message: `${file} declares authentication type \`${candidate.auth.type}\`, which this version cannot execute`,
    }
  }
  if (!candidate.health_probe) {
    return {
      kind: 'no_probe',
      file,
      message: `${file} declares no health probe, so there is nothing to verify against`,
    }
  }

  const probe = candidate.health_probe
  const validated = validateTarget({
    path: probe.path,
    query: probe.query,
    allowedOrigins: candidate.origins,
    basePath: candidate.base_path,
  })
  if (!validated.ok) {
    return {
      kind: 'invalid',
      file,
      message: `the declared probe is not a valid target: ${validated.rejection.code}: ${validated.rejection.message}`,
    }
  }

  const fingerprint = authorityFingerprint(candidate)
  const hash = contractHash(candidate)

  // The grant must already have been activated against THIS candidate file.
  let components = new Map<string, string>()
  if (candidate.auth.type !== 'none') {
    const readiness = services.grants.readinessFor(candidate, fingerprint, request.account)
    if (readiness.readiness === 'no_grant' || readiness.readiness === 'fingerprint_mismatch') {
      return {
        kind: 'missing_grant',
        file,
        api_id: candidate.api_id,
        profile_id: candidate.profile_id,
        authority_fingerprint: fingerprint,
        message: `${readiness.message}. Bind a grant to ${fingerprint} by hand before verifying.`,
      }
    }
    const account = services.grants.selectAccount(readiness, request.account)
    if (!account.ok || !account.account) {
      return {
        kind: 'missing_credential',
        file,
        authority_fingerprint: fingerprint,
        message: account.message,
      }
    }
    try {
      components = services.grants.resolveComponents(candidate, fingerprint, account.account.name)
    } catch (error) {
      return { kind: 'missing_credential', file, message: (error as Error).message }
    }
  }

  const sanitized: SanitizedRequest = {
    api_id: candidate.api_id,
    profile_id: candidate.profile_id,
    method: probe.method,
    origin: validated.target.origin,
    path: validated.target.path,
    query: validated.target.query,
    header_names: [],
    response_mode: 'inline',
    redirect_policy_hash: createHash('sha256')
      .update(JSON.stringify(candidate.redirects))
      .digest('hex'),
  }

  // Candidate permission rules are not trusted: the probe always confirms.
  if (!services.channel) {
    return {
      kind: 'no_terminal',
      file,
      request: sanitized,
      message:
        'verification always requires an interactive confirmation; run `apimanac verify` on a controlling terminal',
    }
  }
  const accepted = await services.channel.confirm(previewOf(sanitized))
  if (!accepted) {
    return {
      kind: 'declined',
      file,
      request: sanitized,
      message: 'the verification probe was declined',
    }
  }

  const headers: Record<string, string> = {}
  const query: [string, string][] = [
    ...validated.target.query.map(([n, v]) => [n, v] as [string, string]),
  ]
  const needles: string[] = [...components.values()]
  for (const placement of candidate.auth.placements) {
    if (placement.kind === 'basic') {
      const pair = `${components.get(placement.username) ?? ''}:${components.get(placement.password) ?? ''}`
      const wire = `Basic ${Buffer.from(pair, 'utf8').toString('base64')}`
      headers[placement.header] = wire
      needles.push(pair, wire)
      continue
    }
    let value = placement.template
    for (const [name, resolved] of components) value = value.replace(`{${name}}`, resolved)
    if (placement.kind === 'header') headers[placement.header] = value
    else query.push([placement.parameter, value])
    needles.push(value)
  }

  const target = {
    ...validated.target,
    query,
    url: `${validated.target.origin}${validated.target.path}${
      query.length
        ? `?${query.map(([n, v]) => `${encodeURIComponent(n)}=${encodeURIComponent(v)}`).join('&')}`
        : ''
    }`,
  }

  const result = await send(
    {
      method: probe.method,
      target,
      headers,
      responseMode: 'inline',
      scanner: needles.length ? new EchoScanner(buildNeedles(needles)) : undefined,
      credentialed: needles.length > 0,
    },
    { ...transportPolicyFor(candidate), timeoutMs: LIMITS.requestTimeoutMs },
  )

  if (result.kind === 'credential_echo') {
    return {
      kind: 'credential_echo_detected',
      file,
      request: sanitized,
      message: result.message,
    }
  }
  if (result.kind === 'failure') {
    services.health?.record(candidate.api_id, candidate.profile_id, {
      transportFailure: result.code === 'timeout' ? 'timeout' : 'connection',
    })
    return { kind: 'probe_failed', file, request: sanitized, message: result.message }
  }

  services.health?.record(candidate.api_id, candidate.profile_id, {
    status: result.status,
    expectedStatus: probe.expect_status,
  })

  if (result.status !== probe.expect_status) {
    return {
      kind: 'probe_failed',
      file,
      request: sanitized,
      status: result.status,
      message: `the probe returned ${result.status}; the profile declares ${probe.expect_status}`,
    }
  }
  if (probe.expect_body_contains) {
    const body = result.body?.toString('utf8') ?? ''
    if (!body.includes(probe.expect_body_contains)) {
      return {
        kind: 'probe_failed',
        file,
        request: sanitized,
        status: result.status,
        message: 'the probe response did not satisfy the declared content predicate',
      }
    }
  }

  // Evidence records hashes and a sanitized summary — never a response body.
  const timestamp = (services.now?.() ?? new Date()).toISOString()
  const evidence = {
    contract_hash: hash,
    method: probe.method,
    path: validated.target.path,
    status: result.status,
    response_hash: `v1:sha256:${createHash('sha256')
      .update(result.body ?? Buffer.alloc(0))
      .digest('hex')}`,
    timestamp,
    tool_version: TOOL_VERSION,
  }
  const updated = { ...(document as Record<string, unknown>) }
  updated.verification = { state: 'verified', verified_at: timestamp, evidence }
  ExecutionProfile.parse(updated)
  writeFileSync(absolute, stringify(updated))

  return {
    kind: 'verified',
    file,
    api_id: candidate.api_id,
    profile_id: candidate.profile_id,
    contract_hash: hash,
    authority_fingerprint: fingerprint,
    status: result.status,
    request: sanitized,
    evidence_written: true,
    message: `${file} is now marked verified as an uncommitted worktree change; a reviewer must commit the profile and its evidence together before it becomes eligible`,
  }
}
