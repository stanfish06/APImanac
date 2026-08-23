import type { GrantStore } from '../auth/grants'
import { authorityFingerprint, contractHash } from '../catalog/canonical'
import { buildIdentityIndex } from '../catalog/identity'
import { loadWorkingTree, type CatalogSnapshot } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import type { HealthStore } from '../execute/health'
import { evaluateEligibility } from '../policy/eligibility'
import { describeOperations } from '../policy/permissions'
import type { ExecutionProfile } from '../schema/execution'
import type { CredentialReadiness, HealthState, PermissionDecision } from '../schema/vocab'
import { isExecutableAuthType } from '../schema/vocab'

/**
 * Exact inspection. The output carries the contract hash and the authority
 * fingerprint — the value an operator pastes into `grants.yaml` — and bounds
 * operation and specification output rather than emitting a whole document.
 */

export const OPERATION_LIMIT = 25
export const SPEC_SUMMARY_LIMIT = 600

export interface ShownProfile {
  readonly profile_id: string
  readonly file: string
  readonly description: string
  readonly origins: string[]
  readonly base_path?: string
  readonly network_scope: string
  readonly auth_type: string
  readonly credential_id?: string
  readonly components: string[]
  readonly verification: string
  readonly verified_at?: string
  readonly contract_hash: string
  readonly authority_fingerprint: string
  readonly eligible: boolean
  readonly ineligible_reason?: string
  /** This build can execute this profile's auth shape. */
  readonly auth_supported: boolean
  readonly draft: boolean
  readonly readiness: CredentialReadiness
  readonly health: HealthState
  readonly health_last_checked?: string
  readonly cache_enabled: boolean
  readonly operations: { method: string; path: string; decision: PermissionDecision }[]
  readonly operations_truncated: boolean
  readonly spec?: { id: string; url: string; format?: string; byte_size?: number; summary?: string }
}

export interface ShownRecord {
  readonly id: string
  readonly requested: string
  readonly matched_alias?: string
  readonly redirected_from?: string
  readonly name: string
  readonly description: string
  readonly homepage?: string
  readonly documentation?: string
  readonly categories: string[]
  readonly tags: string[]
  readonly aliases: string[]
  readonly lifecycle: string
  readonly curation: string
  readonly draft: boolean
  readonly sources: string[]
  readonly capabilities: string[]
  /** At least one profile passes every eligibility condition, so a call can go through. */
  readonly callable: boolean
  /** At least one profile's auth shape is executable by this build. */
  readonly auth_supported: boolean
  readonly profiles: ShownProfile[]
}

export interface ShowServices {
  readonly grants?: GrantStore
  readonly health?: HealthStore
}

function summarize(text: string | undefined): string | undefined {
  if (!text) return undefined
  return text.length <= SPEC_SUMMARY_LIMIT ? text : `${text.slice(0, SPEC_SUMMARY_LIMIT)}…`
}

export function showRecord(
  root: CatalogRoot,
  requested: string,
  services: ShowServices = {},
  snapshot: CatalogSnapshot = loadWorkingTree(root.path, root.git),
): ShownRecord | undefined {
  const index = buildIdentityIndex(snapshot.records)
  const resolution = index.resolve(requested)
  if (!resolution) return undefined
  const entry = snapshot.records.get(resolution.id)
  if (!entry) return undefined
  const record = entry.value

  const profiles: ShownProfile[] = []
  for (const candidate of [...snapshot.profiles.values()].sort((a, b) =>
    a.file < b.file ? -1 : 1,
  )) {
    if (candidate.value.api_id !== record.id) continue
    profiles.push(describeProfile(root, candidate.value, candidate.file, candidate.draft, services))
  }

  return {
    id: record.id,
    requested,
    matched_alias: resolution.viaAlias,
    redirected_from: resolution.viaMerge?.[0],
    name: record.name,
    description: record.description,
    homepage: record.homepage,
    documentation: record.documentation,
    categories: record.categories,
    tags: record.tags,
    aliases: index.aliasesOf(record.id),
    lifecycle: record.lifecycle,
    curation: record.curation,
    draft: entry.draft,
    sources: record.sources,
    capabilities: record.capabilities,
    callable: profiles.some((profile) => profile.eligible),
    auth_supported: profiles.some((profile) => profile.auth_supported),
    profiles,
  }
}

function describeProfile(
  root: CatalogRoot,
  profile: ExecutionProfile,
  file: string,
  draft: boolean,
  services: ShowServices,
): ShownProfile {
  const eligibility = evaluateEligibility(root, profile.api_id, profile.profile_id)
  const fingerprint = authorityFingerprint(profile)
  const readiness = services.grants?.readinessFor(profile, fingerprint)
  const health = services.health?.stateOf(profile.api_id, profile.profile_id)
  const { operations, truncated } = describeOperations(profile, OPERATION_LIMIT)
  const spec = profile.spec_ref

  return {
    profile_id: profile.profile_id,
    file,
    description: profile.description,
    origins: profile.origins,
    base_path: profile.base_path,
    network_scope: profile.network_scope,
    auth_type: profile.auth.type,
    credential_id: profile.auth.credential_id,
    components: profile.auth.components.map((component) => component.name),
    verification: profile.verification.state,
    verified_at: profile.verification.verified_at,
    contract_hash: contractHash(profile),
    authority_fingerprint: fingerprint,
    eligible: eligibility.eligible,
    ineligible_reason: eligibility.eligible ? undefined : eligibility.reason,
    auth_supported: isExecutableAuthType(profile.auth.type),
    draft,
    readiness: readiness?.readiness ?? (profile.auth.type === 'none' ? 'not_required' : 'no_grant'),
    health: health?.state ?? 'unknown',
    health_last_checked: health?.last_checked || undefined,
    cache_enabled: profile.cache.enabled,
    operations,
    operations_truncated: truncated,
    // A large specification yields a bounded summary and a reference, never the document.
    spec: spec
      ? {
          id: spec.id,
          url: spec.url,
          format: spec.format,
          byte_size: spec.byte_size,
          summary: summarize(spec.summary),
        }
      : undefined,
  }
}

export function formatShownRecord(record: ShownRecord): string {
  const lines = [
    `${record.id}  ${record.name}`,
    record.matched_alias ? `resolved from alias \`${record.matched_alias}\`` : undefined,
    record.redirected_from ? `redirected from merged id \`${record.redirected_from}\`` : undefined,
    record.description,
    `lifecycle=${record.lifecycle} curation=${record.curation}${record.draft ? ' draft' : ''}`,
    record.categories.length ? `categories: ${record.categories.join(', ')}` : undefined,
    record.tags.length ? `tags: ${record.tags.join(', ')}` : undefined,
    record.aliases.length ? `aliases: ${record.aliases.join(', ')}` : undefined,
    record.capabilities.length ? `capabilities:\n  ${record.capabilities.join('\n  ')}` : undefined,
  ].filter((line): line is string => Boolean(line))

  for (const profile of record.profiles) {
    lines.push('')
    lines.push(`profile ${profile.profile_id}  (${profile.file})`)
    lines.push(
      `  origins: ${profile.origins.join(', ')}${profile.base_path ? ` base_path=${profile.base_path}` : ''}`,
    )
    lines.push(
      `  auth: ${profile.auth_type}${profile.credential_id ? ` credential=${profile.credential_id}` : ''}${profile.components.length ? ` components=${profile.components.join(',')}` : ''}`,
    )
    lines.push(
      `  verification: ${profile.verification}${profile.verified_at ? ` at ${profile.verified_at}` : ''}`,
    )
    lines.push(`  contract hash:        ${profile.contract_hash}`)
    lines.push(`  authority fingerprint: ${profile.authority_fingerprint}`)
    lines.push(
      `  eligible: ${profile.eligible}${profile.ineligible_reason ? ` — ${profile.ineligible_reason}` : ''}`,
    )
    lines.push(
      `  readiness: ${profile.readiness}  health: ${profile.health}${profile.health_last_checked ? ` (last checked ${profile.health_last_checked})` : ''}`,
    )
    if (profile.operations.length) {
      lines.push('  operations:')
      for (const operation of profile.operations) {
        lines.push(`    ${operation.decision.padEnd(7)} ${operation.method} ${operation.path}`)
      }
      if (profile.operations_truncated) lines.push('    …more operations not shown')
    }
    if (profile.spec) {
      lines.push(
        `  specification: ${profile.spec.id} ${profile.spec.url}${profile.spec.byte_size ? ` (${profile.spec.byte_size} bytes)` : ''}`,
      )
      if (profile.spec.summary) lines.push(`    ${profile.spec.summary}`)
    }
  }
  return lines.join('\n')
}
