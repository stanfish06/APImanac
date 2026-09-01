import type { GrantStore } from '../auth/grants'
import { profilePath } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import {
  blobDigest,
  evaluateWorkflowEligibility,
  type ResolvedBinding,
  resolveCommittedIdentity,
} from '../policy/eligibility'
import { BINDING_PROFILE_PATTERN, type ParamIssue, validateParams } from '../schema/workflow'
import type { ResponseCache } from './cache'
import { type CallOutcome, callApi } from './call'
import {
  type ApprovalTokens,
  type ConfirmationChannel,
  confirmScript,
  SCRIPT_SOURCE_MAX_BYTES,
  type ScriptApprovalSubject,
  type ScriptApprovals,
  serializedChannel,
} from './confirm'
import type { HealthStore } from './health'
import { type BridgeCallRequest, resolveDeno, runSandbox, type SandboxResult } from './sandbox'

/**
 * Workflow and ad-hoc script runs. Both tiers share one runner: they differ
 * only in where the source comes from (committed blob vs approved subject) and
 * in what gates the spawn (eligibility vs single-use approval). Every bridged
 * call goes through `callApi`, so profile policy is identical to `call_api`.
 */

export const RESULT_LIMITS = {
  maxBytes: 1024 * 1024,
  maxDepth: 32,
  maxMembers: 10000,
} as const

export type RunOutcomeKind =
  | 'success'
  | 'invalid_params'
  | 'ineligible'
  | 'approval_required'
  | 'approval_declined'
  | 'script_error'
  | 'serialization_error'
  | 'protocol_error'
  | 'sandbox_unavailable'
  | 'cancelled'

export interface WorkflowRunOutcome {
  readonly kind: RunOutcomeKind
  readonly message: string
  readonly api_id?: string
  readonly workflow_id?: string
  /** The script's returned value; present only on success. */
  readonly result?: unknown
  readonly reasons?: string[]
  readonly issues?: ParamIssue[]
  readonly calls: number
  /** Set when any bridged call carried remote content; the result inherits it. */
  readonly remote_content?: true
  /** Bounded tail of the script's stderr — untrusted script output. */
  readonly stderr?: string
}

export interface RunServices {
  readonly grants: GrantStore
  readonly tokens: ApprovalTokens
  readonly scriptApprovals: ScriptApprovals
  readonly health?: HealthStore
  readonly cache?: ResponseCache
  readonly channel?: ConfirmationChannel
  readonly confirmationHint?: string
  readonly signal?: AbortSignal
}

/** Depth/member/byte-bounded check that a script result is plain JSON data. */
export function checkResultValue(value: unknown): { ok: true } | { ok: false; message: string } {
  let members = 0
  const walk = (node: unknown, depth: number, path: string): string | undefined => {
    members += 1
    if (members > RESULT_LIMITS.maxMembers) {
      return `the result exceeds ${RESULT_LIMITS.maxMembers} values`
    }
    if (depth > RESULT_LIMITS.maxDepth) {
      return `the result exceeds a nesting depth of ${RESULT_LIMITS.maxDepth}`
    }
    if (node === null) return undefined
    switch (typeof node) {
      case 'string':
      case 'boolean':
        return undefined
      case 'number':
        return Number.isFinite(node) ? undefined : `${path || '$'} is not a finite number`
      case 'object':
        break
      default:
        return `${path || '$'} is a ${typeof node}, which is not plain JSON data`
    }
    if (Array.isArray(node)) {
      for (let i = 0; i < node.length; i++) {
        const failure = walk(node[i], depth + 1, `${path}[${i}]`)
        if (failure) return failure
      }
      return undefined
    }
    const proto = Object.getPrototypeOf(node)
    if (proto !== Object.prototype && proto !== null) {
      return `${path || '$'} is a class instance, which is not plain JSON data`
    }
    for (const [key, child] of Object.entries(node as Record<string, unknown>)) {
      const failure = walk(child, depth + 1, path ? `${path}.${key}` : key)
      if (failure) return failure
    }
    return undefined
  }
  const failure = walk(value, 0, '')
  if (failure) return { ok: false, message: failure }
  const bytes = Buffer.byteLength(JSON.stringify(value) ?? 'null', 'utf8')
  if (bytes > RESULT_LIMITS.maxBytes) {
    return {
      ok: false,
      message: `the serialized result is ${bytes} bytes; the bound is ${RESULT_LIMITS.maxBytes}`,
    }
  }
  return { ok: true }
}

/**
 * The call view a script receives: the sanitized public fields only. `file`
 * never appears because the bridge refuses the file response mode.
 */
function scriptCallView(outcome: CallOutcome): Record<string, unknown> {
  return {
    outcome: outcome.kind,
    message: outcome.message,
    api_id: outcome.api_id,
    profile_id: outcome.profile_id,
    decision: outcome.decision,
    status: outcome.status,
    headers: outcome.headers,
    body: outcome.body,
    body_encoding: outcome.body_encoding,
    bytes: outcome.bytes,
    from_cache: outcome.from_cache,
    missing_components: outcome.missing_components,
    remote_content: outcome.remote_content ? true : undefined,
  }
}

interface ExecuteArgs {
  readonly root: CatalogRoot
  readonly scriptSource: Buffer
  readonly params: Record<string, unknown>
  readonly bindings: readonly ResolvedBinding[]
  readonly services: RunServices
  readonly label: { api_id?: string; workflow_id?: string }
}

async function executeInSandbox(args: ExecuteArgs): Promise<WorkflowRunOutcome> {
  const resolution = resolveDeno()
  if (!resolution.ok) {
    return { kind: 'sandbox_unavailable', message: resolution.message, calls: 0, ...args.label }
  }
  const { root, services } = args
  const channel = services.channel ? serializedChannel(services.channel) : undefined
  const bound = new Map(args.bindings.map((binding) => [binding.profile, binding]))
  let calls = 0
  let sawRemote = false

  const onCall = async (profile: string, request: BridgeCallRequest): Promise<unknown> => {
    const binding = bound.get(profile)
    if (!binding) {
      return {
        outcome: 'unbound_profile',
        message: `\`${profile}\` is not bound by this run; bound: ${[...bound.keys()].join(', ') || 'none'}`,
      }
    }
    const [bindApi, bindProfile] = profile.split('/') as [string, string]
    calls += 1
    const outcome = await callApi(
      {
        root,
        api: bindApi,
        profile: bindProfile,
        method: request.method,
        path: request.path,
        query: request.query,
        headers: request.headers,
        responseMode: 'inline',
        body:
          request.body_json !== undefined
            ? { kind: 'json', value: request.body_json }
            : request.body_text !== undefined
              ? { kind: 'text', value: request.body_text }
              : request.body_form !== undefined
                ? { kind: 'form', value: request.body_form }
                : undefined,
      },
      {
        grants: services.grants,
        tokens: services.tokens,
        health: services.health,
        cache: services.cache,
        channel,
        confirmationHint: services.confirmationHint,
      },
    )
    if (outcome.remote_content) sawRemote = true
    return scriptCallView(outcome)
  }

  const result: SandboxResult = await runSandbox({
    deno: resolution.deno,
    scriptSource: args.scriptSource,
    params: args.params,
    onCall,
    signal: services.signal,
  })

  const stderr = 'stderr' in result && result.stderr ? result.stderr : undefined
  const base = { calls, stderr, ...args.label }
  switch (result.kind) {
    case 'done': {
      const check = checkResultValue(result.value)
      if (!check.ok) {
        return { kind: 'serialization_error', message: check.message, ...base }
      }
      return {
        kind: 'success',
        message: 'the script completed',
        result: result.value,
        remote_content: sawRemote ? true : undefined,
        ...base,
      }
    }
    case 'fail':
      return { kind: 'script_error', message: result.message, ...base }
    case 'protocol_error':
      return { kind: 'protocol_error', message: result.message, ...base }
    case 'cancelled':
      return { kind: 'cancelled', message: 'the run was cancelled', ...base }
    case 'spawn_error':
      return { kind: 'sandbox_unavailable', message: result.message, ...base }
  }
}

export interface WorkflowRunRequest {
  readonly root: CatalogRoot
  readonly api: string
  readonly workflow: string
  readonly params?: unknown
}

export async function runWorkflow(
  request: WorkflowRunRequest,
  services: RunServices,
): Promise<WorkflowRunOutcome> {
  const identity = resolveCommittedIdentity(request.root, request.api)
  if (!identity) {
    return {
      kind: 'ineligible',
      message: `\`${request.api}\` is not a committed canonical id or alias in this catalog`,
      calls: 0,
    }
  }
  const label = { api_id: identity.id, workflow_id: request.workflow }
  const eligibility = evaluateWorkflowEligibility(request.root, identity.id, request.workflow)
  if (!eligibility.eligible) {
    return {
      kind: 'ineligible',
      message: `workflow \`${identity.id}/${request.workflow}\` is not runnable`,
      reasons: eligibility.reasons,
      calls: 0,
      ...label,
    }
  }
  const params = validateParams(eligibility.definition.params, request.params)
  if (!params.ok) {
    return {
      kind: 'invalid_params',
      message: 'the parameters do not satisfy the declared schema',
      issues: params.issues,
      calls: 0,
      ...label,
    }
  }
  return executeInSandbox({
    root: request.root,
    scriptSource: eligibility.scriptBytes,
    params: params.value,
    bindings: eligibility.bindings,
    services,
    label,
  })
}

export interface ScriptRunRequest {
  readonly root: CatalogRoot
  readonly source: string
  readonly bindings: readonly string[]
  readonly params?: unknown
}

export async function runScript(
  request: ScriptRunRequest,
  services: RunServices,
): Promise<WorkflowRunOutcome> {
  const resolution = resolveDeno()
  if (!resolution.ok) {
    return { kind: 'sandbox_unavailable', message: resolution.message, calls: 0 }
  }
  const source = Buffer.from(request.source, 'utf8')
  if (source.byteLength > SCRIPT_SOURCE_MAX_BYTES) {
    return {
      kind: 'approval_required',
      message: `the script is ${source.byteLength} bytes; sources beyond ${SCRIPT_SOURCE_MAX_BYTES} bytes cannot be fully previewed, so the run is refused`,
      calls: 0,
    }
  }
  if (
    request.params !== undefined &&
    (typeof request.params !== 'object' || request.params === null || Array.isArray(request.params))
  ) {
    return {
      kind: 'invalid_params',
      message: 'params must be an object',
      calls: 0,
    }
  }
  const params = (request.params ?? {}) as Record<string, unknown>
  const paramsCheck = checkResultValue(params)
  if (!paramsCheck.ok) {
    return { kind: 'invalid_params', message: paramsCheck.message, calls: 0 }
  }

  const reasons: string[] = []
  const bindings: ResolvedBinding[] = []
  const seen = new Set<string>()
  for (const profile of request.bindings) {
    if (!BINDING_PROFILE_PATTERN.test(profile)) {
      reasons.push(`\`${profile}\` is not \`<api-id>/<profile-id>\``)
      continue
    }
    if (seen.has(profile)) continue
    seen.add(profile)
    const [bindApi, bindProfile] = profile.split('/') as [string, string]
    const blob = request.root.git.available
      ? request.root.git.readHeadBlob(profilePath(bindApi, bindProfile))
      : undefined
    if (!blob?.present || !blob.bytes) {
      reasons.push(
        `\`${profile}\` names ${profilePath(bindApi, bindProfile)}, which is not committed`,
      )
      continue
    }
    bindings.push({ profile, blob_sha256: blobDigest(blob.bytes as Buffer) })
  }
  if (bindings.length === 0) reasons.push('an ad-hoc script binds at least one committed profile')
  if (reasons.length) {
    return {
      kind: 'ineligible',
      message: 'the requested bindings do not resolve',
      reasons,
      calls: 0,
    }
  }

  if (!services.channel) {
    return {
      kind: 'approval_required',
      message:
        services.confirmationHint ??
        'an ad-hoc script requires an interactive approval of its full source; none is available here',
      calls: 0,
    }
  }

  const subject: ScriptApprovalSubject = {
    source,
    params,
    bindings,
    runtime: `deno/${resolution.deno.version}`,
  }
  const approval = await confirmScript(services.channel, services.scriptApprovals, subject)
  if (!approval.accepted) {
    return {
      kind: 'approval_declined',
      message: 'the script approval was declined; nothing was executed',
      calls: 0,
    }
  }
  // Single-use, consumed against the same in-memory subject at spawn time.
  const consumed = services.scriptApprovals.consume(approval.token, subject)
  if (!consumed.ok) {
    return { kind: 'approval_required', message: consumed.message, calls: 0 }
  }

  return executeInSandbox({
    root: request.root,
    scriptSource: source,
    params,
    bindings,
    services,
    label: {},
  })
}
