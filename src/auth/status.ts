import { authorityFingerprint } from '../catalog/canonical'
import { loadWorkingTree } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import { evaluateEligibility } from '../policy/eligibility'
import type { CredentialReadiness } from '../schema/vocab'
import { isExecutableAuthType } from '../schema/vocab'
import { GrantStore, type GrantStoreOptions } from './grants'

/**
 * `auth status` is read-only and offline. It reports whether a binding exists
 * and resolves — never a credential value, an environment-variable name, or a
 * path.
 */

export interface ProfileStatus {
  readonly api_id: string
  readonly profile_id: string
  readonly file: string
  readonly auth_type: string
  readonly credential_id?: string
  readonly supported: boolean
  readonly required_components: string[]
  readonly grant_present: boolean
  readonly fingerprint_matches: boolean
  /** The fingerprint the user binds a grant to, as printed by `show`. */
  readonly authority_fingerprint: string
  /** True when the profile file is untracked, modified, or deleted. */
  readonly draft: boolean
  readonly readiness: CredentialReadiness
  readonly missing_components: string[]
  readonly ambiguous_accounts?: string[]
  readonly message: string
}

export interface AuthStatusReport {
  readonly catalog_root: string
  readonly grants_file: string
  readonly grants_file_present: boolean
  readonly profiles: ProfileStatus[]
}

export function authStatus(root: CatalogRoot, options: GrantStoreOptions = {}): AuthStatusReport {
  const store = GrantStore.load(options)
  const snapshot = loadWorkingTree(root.path, root.git)
  const profiles: ProfileStatus[] = []

  for (const entry of [...snapshot.profiles.values()].sort((a, b) => (a.file < b.file ? -1 : 1))) {
    const worktree = entry.value
    if (worktree.auth.type === 'none') continue

    const eligibility = evaluateEligibility(root, worktree.api_id, worktree.profile_id)
    // Ordinary execution binds to the committed profile; a draft binds to the
    // worktree candidate, which is what `verify` compares against.
    const bound = eligibility.eligible ? eligibility.profile : worktree
    const fingerprint = eligibility.eligible
      ? eligibility.authorityFingerprint
      : authorityFingerprint(worktree)
    const readiness = store.readinessFor(bound, fingerprint)
    const selection = store.selectAccount(readiness)

    profiles.push({
      api_id: worktree.api_id,
      profile_id: worktree.profile_id,
      file: entry.file,
      auth_type: worktree.auth.type,
      credential_id: worktree.auth.credential_id,
      supported: isExecutableAuthType(worktree.auth.type),
      required_components: readiness.requiredComponents,
      grant_present: readiness.grantPresent,
      fingerprint_matches: readiness.readiness !== 'fingerprint_mismatch' && readiness.grantPresent,
      authority_fingerprint: fingerprint,
      draft: entry.draft,
      readiness: readiness.readiness,
      missing_components: [...new Set(readiness.accounts.flatMap((account) => account.missing))],
      ambiguous_accounts:
        selection.readiness === 'ambiguous_account' ? selection.candidates : undefined,
      message: readiness.message,
    })
  }

  return {
    catalog_root: root.path,
    grants_file: store.file,
    grants_file_present: store.present,
    profiles,
  }
}

export function formatAuthStatus(report: AuthStatusReport): string {
  if (report.profiles.length === 0) return 'no profile in this catalog requires a credential'
  return report.profiles
    .map((profile) => {
      const parts = [
        `${profile.api_id}/${profile.profile_id}`,
        profile.readiness,
        `auth=${profile.auth_type}${profile.supported ? '' : ' (not executable in this version)'}`,
        `grant=${profile.grant_present ? 'present' : 'none'}`,
        `fingerprint=${profile.fingerprint_matches ? 'matches' : 'unbound'}`,
      ]
      if (profile.missing_components.length) {
        parts.push(`missing=${profile.missing_components.join(',')}`)
      }
      if (profile.ambiguous_accounts?.length) {
        parts.push(`ambiguous=${profile.ambiguous_accounts.join(',')}`)
      }
      if (profile.draft) parts.push('draft')
      return parts.join('  ')
    })
    .join('\n')
}
