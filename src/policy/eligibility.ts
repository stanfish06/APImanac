import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse } from 'yaml'
import { authorityFingerprint, contractHash, sha256Tagged } from '../catalog/canonical'
import { describePathState } from '../catalog/git'
import { buildIdentityIndex } from '../catalog/identity'
import { loadCommitted, profilePath, workflowPath, workflowScriptPath } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import { ExecutionProfile } from '../schema/execution'
import { isExecutableAuthType } from '../schema/vocab'
import { WorkflowDefinition } from '../schema/workflow'

/**
 * Whether a profile may be executed. The decision is a live read of the
 * selected profile's `HEAD` blob compared byte for byte with the worktree file;
 * the derived authority projection is a query convenience and never decides.
 */

export type IneligibilityCode =
  | 'no_snapshot'
  | 'untracked'
  | 'modified'
  | 'deleted'
  | 'filtered'
  | 'unreadable_blob'
  | 'invalid'
  | 'candidate'
  | 'evidence_mismatch'
  | 'unsupported_auth'
  | 'not_found'

export interface EligibleProfile {
  readonly eligible: true
  readonly file: string
  /** Parsed from the `HEAD` blob, never from the worktree file. */
  readonly profile: ExecutionProfile
  readonly contractHash: string
  readonly authorityFingerprint: string
}

export interface IneligibleProfile {
  readonly eligible: false
  readonly file: string
  readonly code: IneligibilityCode
  readonly reason: string
  /** Top-level fields that differ between the worktree file and `HEAD`. */
  readonly differingFields?: string[]
}

export type Eligibility = EligibleProfile | IneligibleProfile

function differingTopLevelFields(worktree: unknown, committed: unknown): string[] {
  const left = (worktree ?? {}) as Record<string, unknown>
  const right = (committed ?? {}) as Record<string, unknown>
  const keys = new Set([...Object.keys(left), ...Object.keys(right)])
  const differing: string[] = []
  for (const key of [...keys].sort()) {
    if (JSON.stringify(left[key]) !== JSON.stringify(right[key])) differing.push(key)
  }
  return differing
}

/**
 * Evaluate every catalog-side condition. Grant matching is layered on top by
 * the credentials layer, which owns the local binding.
 */
export function evaluateEligibility(
  root: CatalogRoot,
  apiId: string,
  profileId: string,
): Eligibility {
  const file = profilePath(apiId, profileId)
  const ineligible = (
    code: IneligibilityCode,
    reason: string,
    differingFields?: string[],
  ): IneligibleProfile => ({ eligible: false, file, code, reason, differingFields })

  if (!root.git.available) {
    return ineligible(
      'no_snapshot',
      root.noSnapshotReason ?? describePathState('no_snapshot', file),
    )
  }
  if (root.git.isFiltered(file)) {
    return ineligible('filtered', describePathState('filtered', file))
  }

  // The live comparison, not the derived store, decides.
  const blob = root.git.readHeadBlob(file)
  const absolute = join(root.path, file)
  const worktreeBytes = existsSync(absolute) ? readFileSync(absolute) : undefined

  if (!blob.present) {
    if (!worktreeBytes)
      return ineligible('not_found', `${file} exists in neither HEAD nor the worktree`)
    if (blob.reason?.startsWith('not present in HEAD')) {
      return ineligible('untracked', describePathState('untracked', file))
    }
    return ineligible(
      'unreadable_blob',
      `${describePathState('unreadable_blob', file)}: ${blob.reason}`,
    )
  }
  if (!worktreeBytes) return ineligible('deleted', describePathState('tracked_deleted', file))

  const committedBytes = blob.bytes as Buffer
  if (!worktreeBytes.equals(committedBytes)) {
    const differing = differingTopLevelFields(
      safeParse(worktreeBytes.toString('utf8')),
      safeParse(committedBytes.toString('utf8')),
    )
    return ineligible(
      'modified',
      `${describePathState('tracked_modified', file)}${differing.length ? `: ${differing.join(', ')}` : ''}`,
      differing,
    )
  }

  const parsed = ExecutionProfile.safeParse(safeParse(committedBytes.toString('utf8')))
  if (!parsed.success) {
    return ineligible(
      'invalid',
      `${file} does not validate: ${parsed.error.issues.map((issue) => `${issue.path.join('.')}: ${issue.message}`).join('; ')}`,
    )
  }
  const profile = parsed.data
  if (profile.api_id !== apiId || profile.profile_id !== profileId) {
    return ineligible('invalid', `${file} declares ${profile.api_id}/${profile.profile_id}`)
  }

  if (profile.verification.state !== 'verified') {
    return ineligible(
      'candidate',
      `${file} is a candidate; run \`apimanac verify ${apiId} --profile ${profileId}\` and have a reviewer commit the evidence`,
    )
  }

  const computed = contractHash(profile)
  const recorded = profile.verification.evidence?.contract_hash
  if (recorded !== computed) {
    return ineligible(
      'evidence_mismatch',
      `${file} records evidence for ${recorded} but hashes to ${computed}`,
    )
  }

  if (!isExecutableAuthType(profile.auth.type)) {
    return ineligible(
      'unsupported_auth',
      `${file} declares authentication type \`${profile.auth.type}\`, which this version cannot execute`,
    )
  }

  return {
    eligible: true,
    file,
    profile,
    contractHash: computed,
    authorityFingerprint: authorityFingerprint(profile),
  }
}

function safeParse(text: string): unknown {
  try {
    return parse(text)
  } catch {
    return undefined
  }
}

/**
 * Identity for execution comes from the committed snapshot: a draft alias,
 * merge redirect, or profile link never changes what a call resolves to.
 */
export function committedProfilesFor(root: CatalogRoot, apiId: string): string[] {
  if (!root.git.available) return []
  const prefix = `catalog/execution/${apiId}/`
  return (
    [...root.git.committedPaths()]
      .filter((path) => path.startsWith(prefix) && path.endsWith('.yaml'))
      .map((path) => path.slice(prefix.length, -'.yaml'.length))
      // A nested path is never a profile id; `workflows/…` lives here too.
      .filter((id) => !id.includes('/'))
      .sort()
  )
}

export function committedWorkflowsFor(root: CatalogRoot, apiId: string): string[] {
  if (!root.git.available) return []
  const prefix = `catalog/execution/${apiId}/workflows/`
  return [...root.git.committedPaths()]
    .filter((path) => path.startsWith(prefix) && path.endsWith('.yaml'))
    .map((path) => path.slice(prefix.length, -'.yaml'.length))
    .filter((id) => !id.includes('/'))
    .sort()
}

/** Tagged SHA-256 of exact blob bytes — the value a workflow binding pins. */
export function blobDigest(bytes: Buffer): string {
  return sha256Tagged(bytes)
}

export interface ResolvedBinding {
  readonly profile: string
  readonly blob_sha256: string
}

export interface EligibleWorkflow {
  readonly eligible: true
  readonly definitionFile: string
  readonly scriptFile: string
  /** Parsed from the `HEAD` blob, never from the worktree file. */
  readonly definition: WorkflowDefinition
  /** The committed script bytes; the sandbox executes exactly these. */
  readonly scriptBytes: Buffer
  readonly bindings: readonly ResolvedBinding[]
}

export interface IneligibleWorkflow {
  readonly eligible: false
  readonly definitionFile: string
  readonly scriptFile: string
  /** Every unmet condition, not only the first. */
  readonly reasons: string[]
}

export type WorkflowEligibility = EligibleWorkflow | IneligibleWorkflow

/**
 * Every workflow-side condition, resolved against one `HEAD` snapshot: both
 * files tracked and byte-identical, the definition valid, and every binding's
 * pinned digest equal to the bound profile's committed blob. The returned
 * script bytes come from the blob, so a worktree edit after this check can
 * never reach execution.
 */
export function evaluateWorkflowEligibility(
  root: CatalogRoot,
  apiId: string,
  workflowId: string,
): WorkflowEligibility {
  const definitionFile = workflowPath(apiId, workflowId)
  const scriptFile = workflowScriptPath(apiId, workflowId)
  const reasons: string[] = []
  const refuse = (): IneligibleWorkflow => ({
    eligible: false,
    definitionFile,
    scriptFile,
    reasons,
  })

  if (!root.git.available) {
    reasons.push(root.noSnapshotReason ?? describePathState('no_snapshot', definitionFile))
    return refuse()
  }

  const files = [definitionFile, scriptFile]
  const blobs = root.git.readHeadBlobs(files)
  const cleanBytes = new Map<string, Buffer>()
  for (const file of files) {
    if (root.git.isFiltered(file)) {
      reasons.push(describePathState('filtered', file))
      continue
    }
    const blob = blobs.get(file)
    const absolute = join(root.path, file)
    const worktree = existsSync(absolute) ? readFileSync(absolute) : undefined
    if (!blob?.present) {
      if (!worktree) reasons.push(`${file} exists in neither HEAD nor the worktree`)
      else if (blob?.reason?.startsWith('not present in HEAD')) {
        reasons.push(describePathState('untracked', file))
      } else {
        reasons.push(`${describePathState('unreadable_blob', file)}: ${blob?.reason}`)
      }
      continue
    }
    if (!worktree) {
      reasons.push(describePathState('tracked_deleted', file))
      continue
    }
    const committed = blob.bytes as Buffer
    if (!worktree.equals(committed)) {
      reasons.push(describePathState('tracked_modified', file))
      continue
    }
    cleanBytes.set(file, committed)
  }

  const definitionBytes = cleanBytes.get(definitionFile)
  if (!definitionBytes) return refuse()

  const parsed = WorkflowDefinition.safeParse(safeParse(definitionBytes.toString('utf8')))
  if (!parsed.success) {
    reasons.push(
      `${definitionFile} does not validate: ${parsed.error.issues
        .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
        .join('; ')}`,
    )
    return refuse()
  }
  const definition = parsed.data
  if (definition.api_id !== apiId || definition.workflow_id !== workflowId) {
    reasons.push(`${definitionFile} declares ${definition.api_id}/${definition.workflow_id}`)
    return refuse()
  }

  const bindingFiles = definition.bindings.map((binding) => {
    const [bindApi, bindProfile] = binding.profile.split('/') as [string, string]
    return { binding, file: profilePath(bindApi, bindProfile) }
  })
  const bindingBlobs = root.git.readHeadBlobs(bindingFiles.map((entry) => entry.file))
  const bindings: ResolvedBinding[] = []
  for (const { binding, file } of bindingFiles) {
    const blob = bindingBlobs.get(file)
    if (!blob?.present || !blob.bytes) {
      reasons.push(`binding \`${binding.profile}\` names ${file}, which is not committed`)
      continue
    }
    const digest = blobDigest(blob.bytes as Buffer)
    if (digest !== binding.blob_sha256) {
      reasons.push(
        `binding \`${binding.profile}\` pins ${binding.blob_sha256} but the committed profile blob is ${digest}; re-review the workflow and update the pin`,
      )
      continue
    }
    bindings.push({ profile: binding.profile, blob_sha256: digest })
  }

  const scriptBytes = cleanBytes.get(scriptFile)
  if (reasons.length || !scriptBytes) return refuse()

  return {
    eligible: true,
    definitionFile,
    scriptFile,
    definition,
    scriptBytes,
    bindings,
  }
}

/** Resolve an id or alias against the committed records only. */
export function resolveCommittedIdentity(
  root: CatalogRoot,
  requested: string,
): { id: string; viaAlias?: string; viaMerge?: readonly string[] } | undefined {
  if (!root.git.available) return undefined
  const index = buildIdentityIndex(loadCommitted(root.git).records)
  return index.resolve(requested)
}
