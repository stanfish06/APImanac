import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse } from 'yaml'
import { authorityFingerprint, contractHash } from '../catalog/canonical'
import { describePathState } from '../catalog/git'
import { buildIdentityIndex } from '../catalog/identity'
import { loadCommitted, profilePath } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import { ExecutionProfile } from '../schema/execution'
import { isExecutableAuthType } from '../schema/vocab'

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
  return [...root.git.committedPaths()]
    .filter((path) => path.startsWith(prefix) && path.endsWith('.yaml'))
    .map((path) => path.slice(prefix.length, -'.yaml'.length))
    .sort()
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
