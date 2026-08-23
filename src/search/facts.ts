import type { GrantStore } from '../auth/grants'
import { authorityFingerprint } from '../catalog/canonical'
import { loadWorkingTree } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import type { HealthStore } from '../execute/health'
import { evaluateEligibility } from '../policy/eligibility'
import type { FactsProvider, ProfileFacts } from './query'

/**
 * Machine-local facts for search and inspection: credential readiness from the
 * activated grants, health from the observation store. Both are per-profile and
 * memoized for the life of one command.
 */
export function localFacts(
  root: CatalogRoot,
  grants: GrantStore,
  health?: HealthStore,
): FactsProvider {
  const cache = new Map<string, ProfileFacts>()
  const profiles = loadWorkingTree(root.path, root.git).profiles

  return {
    factsFor(apiId, profileId) {
      const key = `${apiId}/${profileId}`
      const cached = cache.get(key)
      if (cached) return cached
      const observation = health?.stateOf(apiId, profileId)
      const entry = profiles.get(key)
      let readiness: ProfileFacts['readiness'] = 'no_grant'
      if (entry) {
        // Ordinary execution binds to the committed profile; a draft binds to
        // the worktree candidate, which is what `verify` compares against.
        const eligibility = evaluateEligibility(root, apiId, profileId)
        const bound = eligibility.eligible ? eligibility.profile : entry.value
        const fingerprint = eligibility.eligible
          ? eligibility.authorityFingerprint
          : authorityFingerprint(entry.value)
        readiness = grants.readinessFor(bound, fingerprint).readiness
      }
      const facts: ProfileFacts = {
        readiness,
        health: observation?.state ?? 'unknown',
        lastChecked: observation?.last_checked || undefined,
      }
      cache.set(key, facts)
      return facts
    },
  }
}
