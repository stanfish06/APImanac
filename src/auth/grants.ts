import { existsSync, readFileSync, statSync } from 'node:fs'
import { parse } from 'yaml'
import { ApimanacError } from '../errors'
import { paths } from '../paths'
import type { ExecutionProfile } from '../schema/execution'
import { type Grant, GrantsFile } from '../schema/grant'
import type { CredentialReadiness } from '../schema/vocab'
import { isExecutableAuthType, REQUIRED_COMPONENTS } from '../schema/vocab'
import {
  type ComponentFailure,
  type CredentialProvider,
  defaultProvider,
  isResolved,
} from './providers'

/**
 * Local grants. Nothing here writes: APImanac has no command that creates,
 * edits, activates, or deletes a grant or a credential.
 */

export interface GrantStoreOptions {
  readonly path?: string
  readonly provider?: CredentialProvider
}

export interface AccountReadiness {
  readonly name: string
  readonly default: boolean
  readonly ready: boolean
  readonly missing: string[]
  readonly reason?: string
}

export interface ProfileReadiness {
  readonly readiness: CredentialReadiness
  readonly grantPresent: boolean
  readonly credentialId?: string
  readonly requiredComponents: string[]
  readonly accounts: AccountReadiness[]
  /** Names components only; never a variable name or a path. */
  readonly message: string
}

export interface AccountSelection {
  readonly ok: boolean
  readonly account?: AccountReadiness
  readonly candidates?: string[]
  readonly readiness: CredentialReadiness
  readonly message: string
}

function requiredComponentsOf(profile: ExecutionProfile): string[] {
  const declared = profile.auth.components.map((component) => component.name)
  if (!isExecutableAuthType(profile.auth.type)) return declared
  const required = REQUIRED_COMPONENTS[profile.auth.type]
  return [...new Set([...required, ...declared])]
}

export class GrantStore {
  private readonly grants: Grant[]
  private readonly provider: CredentialProvider
  readonly file: string
  readonly present: boolean
  /** Set when the grants file exists but cannot be used as written. */
  readonly loadError?: string

  private constructor(
    file: string,
    present: boolean,
    grants: Grant[],
    provider: CredentialProvider,
    loadError?: string,
  ) {
    this.file = file
    this.present = present
    this.grants = grants
    this.provider = provider
    this.loadError = loadError
  }

  static load(options: GrantStoreOptions = {}): GrantStore {
    const file = options.path ?? paths.grantsFile()
    const provider = options.provider ?? defaultProvider
    if (!existsSync(file)) return new GrantStore(file, false, [], provider)
    const mode = statSync(file).mode & 0o077
    if (mode !== 0) {
      return new GrantStore(
        file,
        true,
        [],
        provider,
        'the grants file is readable beyond its owner; tighten it to owner-only (0600)',
      )
    }
    let document: unknown
    try {
      document = parse(readFileSync(file, 'utf8'))
    } catch (error) {
      return new GrantStore(
        file,
        true,
        [],
        provider,
        `the grants file is not valid YAML: ${(error as Error).message}`,
      )
    }
    const parsed = GrantsFile.safeParse(document ?? {})
    if (!parsed.success) {
      return new GrantStore(
        file,
        true,
        [],
        provider,
        `the grants file does not validate: ${parsed.error.issues.map((issue) => issue.message).join('; ')}`,
      )
    }
    return new GrantStore(file, true, parsed.data.grants, provider)
  }

  /** Grants a user activated for this exact api and profile. */
  grantsFor(apiId: string, profileId: string): Grant[] {
    return this.grants.filter((grant) => grant.api_id === apiId && grant.profile_id === profileId)
  }

  /**
   * Grants activated against this exact fingerprint whose origins match the
   * profile. Readiness and resolution both go through here, so resolution can
   * never reach a grant readiness rejected.
   */
  private boundGrants(profile: ExecutionProfile, fingerprint: string): Grant[] {
    return this.grantsFor(profile.api_id, profile.profile_id)
      .filter((grant) => grant.authority_fingerprint === fingerprint)
      .filter((grant) => sameOrigins(grant.origins, profile.origins))
  }

  /**
   * Readiness of a profile against the local bindings. `fingerprint` is the
   * profile the operation is bound to: the committed profile for ordinary
   * execution, the worktree candidate for `verify`.
   */
  readinessFor(profile: ExecutionProfile, fingerprint: string, account?: string): ProfileReadiness {
    const required = requiredComponentsOf(profile)
    if (profile.auth.type === 'none') {
      return {
        readiness: 'not_required',
        grantPresent: false,
        requiredComponents: [],
        accounts: [],
        message: 'this profile requires no credential',
      }
    }
    if (!isExecutableAuthType(profile.auth.type)) {
      return {
        readiness: 'unsupported_auth',
        grantPresent: false,
        credentialId: profile.auth.credential_id,
        requiredComponents: required,
        accounts: [],
        message: `authentication type \`${profile.auth.type}\` is described but not executable in this version`,
      }
    }
    if (this.loadError) {
      return {
        readiness: 'no_grant',
        grantPresent: false,
        credentialId: profile.auth.credential_id,
        requiredComponents: required,
        accounts: [],
        message: this.loadError,
      }
    }

    const grants = this.grantsFor(profile.api_id, profile.profile_id)
    if (grants.length === 0) {
      return {
        readiness: 'no_grant',
        grantPresent: false,
        credentialId: profile.auth.credential_id,
        requiredComponents: required,
        accounts: [],
        message: `no activated grant binds credential \`${profile.auth.credential_id}\` (components: ${required.join(', ')}) for ${profile.api_id}/${profile.profile_id}; the user must activate it by hand`,
      }
    }

    const fingerprintMatch = grants.filter((grant) => grant.authority_fingerprint === fingerprint)
    if (fingerprintMatch.length === 0) {
      return {
        readiness: 'fingerprint_mismatch',
        grantPresent: true,
        credentialId: profile.auth.credential_id,
        requiredComponents: required,
        accounts: [],
        message: `the activated grant was bound to a different authority fingerprint; the user must activate a new binding for ${fingerprint}`,
      }
    }

    const originsMatch = this.boundGrants(profile, fingerprint)
    if (originsMatch.length === 0) {
      return {
        readiness: 'fingerprint_mismatch',
        grantPresent: true,
        credentialId: profile.auth.credential_id,
        requiredComponents: required,
        accounts: [],
        message: `the activated grant records different origins than the profile it is being used for; the user must activate a new binding`,
      }
    }

    const accounts: AccountReadiness[] = []
    for (const grant of originsMatch) {
      for (const entry of grant.accounts) {
        const missing: string[] = []
        let reason: string | undefined
        for (const component of required) {
          const reference = entry.components[component]
          if (!reference) {
            missing.push(component)
            continue
          }
          const result = this.provider.resolve(component, reference)
          if (!isResolved(result)) {
            missing.push(component)
            reason ??= (result as ComponentFailure).message
          }
        }
        accounts.push({
          name: entry.name,
          default: entry.default,
          ready: missing.length === 0,
          missing,
          reason,
        })
      }
    }

    const ready = accounts.filter((entry) => entry.ready)
    if (ready.length === 0) {
      const missing = [...new Set(accounts.flatMap((entry) => entry.missing))]
      // The specific per-component failure (missing value, insecure permissions,
      // file outside the credentials directory) names only the component, so it
      // is safe to surface and distinguishes "unset" from "tighten to 0600".
      const reasons = [
        ...new Set(
          accounts
            .map((entry) => entry.reason)
            .filter((reason): reason is string => Boolean(reason)),
        ),
      ]
      return {
        readiness: 'missing_component',
        grantPresent: true,
        credentialId: profile.auth.credential_id,
        requiredComponents: required,
        accounts,
        message: reasons.length
          ? reasons.join('; ')
          : `component(s) ${missing.join(', ')} did not resolve for any account`,
      }
    }
    if (!account && ready.length > 1 && !ready.some((entry) => entry.default)) {
      return {
        readiness: 'ambiguous_account',
        grantPresent: true,
        credentialId: profile.auth.credential_id,
        requiredComponents: required,
        accounts,
        message: `several accounts are ready and none is marked default: ${ready.map((entry) => entry.name).join(', ')}`,
      }
    }
    return {
      readiness: 'ready',
      grantPresent: true,
      credentialId: profile.auth.credential_id,
      requiredComponents: required,
      accounts,
      message: 'a local binding resolves every required component',
    }
  }

  /** Sole ready account, configured default, or structured candidates. */
  selectAccount(readiness: ProfileReadiness, requested?: string): AccountSelection {
    if (readiness.readiness === 'not_required') {
      return { ok: true, readiness: 'not_required', message: 'no credential is required' }
    }
    const ready = readiness.accounts.filter((entry) => entry.ready)
    if (requested) {
      const named = readiness.accounts.find((entry) => entry.name === requested)
      if (!named) {
        return {
          ok: false,
          readiness: 'no_grant',
          message: `no account named \`${requested}\` is bound for this profile`,
        }
      }
      if (!named.ready) {
        // A named-but-unready account is never silently substituted.
        return {
          ok: false,
          readiness: 'missing_component',
          message: `account \`${requested}\` is missing component(s) ${named.missing.join(', ')}`,
        }
      }
      return {
        ok: true,
        account: named,
        readiness: 'ready',
        message: `using account \`${requested}\``,
      }
    }
    if (ready.length === 1) {
      return {
        ok: true,
        account: ready[0],
        readiness: 'ready',
        message: `using the sole ready account`,
      }
    }
    const configuredDefault = ready.find((entry) => entry.default)
    if (configuredDefault) {
      return {
        ok: true,
        account: configuredDefault,
        readiness: 'ready',
        message: `using the configured default account`,
      }
    }
    if (ready.length === 0) {
      return {
        ok: false,
        readiness: readiness.readiness,
        message: readiness.message,
      }
    }
    return {
      ok: false,
      readiness: 'ambiguous_account',
      candidates: ready.map((entry) => entry.name),
      message: `several accounts are ready and none is marked default`,
    }
  }

  /**
   * Resolve one account's components. The fingerprint is required so resolution
   * reads the same grant readiness accepted; values never leave the executor.
   */
  resolveComponents(
    profile: ExecutionProfile,
    fingerprint: string,
    accountName: string,
  ): Map<string, string> {
    const bound = this.boundGrants(profile, fingerprint)
    const matching = bound.filter((entry) =>
      entry.accounts.some((account) => account.name === accountName),
    )
    if (matching.length === 0) {
      throw new ApimanacError(
        'missing_grant',
        `no grant activated against ${fingerprint} binds account \`${accountName}\``,
      )
    }
    if (matching.length > 1) {
      // Two grants binding one account for one profile is ambiguous, not a
      // license to pick either.
      throw new ApimanacError(
        'ambiguous_account',
        `several grants bind account \`${accountName}\` for ${profile.api_id}/${profile.profile_id}; remove the stale one`,
        { account: accountName },
      )
    }
    const grant = matching[0] as Grant
    const account = grant.accounts.find((entry) => entry.name === accountName)
    if (!account) {
      throw new ApimanacError(
        'missing_grant',
        `no activated grant binds account \`${accountName}\``,
      )
    }
    const resolved = new Map<string, string>()
    for (const component of requiredComponentsOf(profile)) {
      const reference = account.components[component]
      if (!reference) {
        throw new ApimanacError(
          'missing_credential',
          `component \`${component}\` is not bound for account \`${accountName}\``,
          { component },
        )
      }
      const result = this.provider.resolve(component, reference)
      if (!isResolved(result)) {
        throw new ApimanacError('missing_credential', result.message, { component })
      }
      resolved.set(component, result.value)
    }
    return resolved
  }
}

function sameOrigins(a: readonly string[], b: readonly string[]): boolean {
  return [...a].sort().join(' ') === [...b].sort().join(' ')
}
