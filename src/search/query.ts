import type { Database } from 'bun:sqlite'
import { ApimanacError } from '../errors'
import {
  AUTH_TYPES,
  CREDENTIAL_READINESS,
  CURATION_STATES,
  HEALTH_STATES,
  LIFECYCLE_STATES,
  VERIFICATION_STATES,
  type AuthType,
  type CredentialReadiness,
  type CurationState,
  type HealthState,
  type Lifecycle,
  type VerificationState,
} from '../schema/vocab'
import { BOOSTS, BOOST_FLOOR, COLUMN_WEIGHTS, DEFAULT_LIMIT, MAX_LIMIT } from './constants'

/**
 * The query layer over the discovery projection. Results carry identity, trust,
 * readiness, and health, and never an endpoint list or credential material.
 */

export interface ProfileSummary {
  readonly profile_id: string
  readonly auth_type: AuthType
  readonly verification: VerificationState
  readonly network_scope: string
  /** This build can execute the profile's auth shape. Not "callable". */
  readonly auth_supported: boolean
  readonly draft: boolean
  readonly readiness: CredentialReadiness
  readonly health: HealthState
  readonly health_last_checked?: string
  readonly verified_at?: string
}

export interface SearchResult {
  readonly id: string
  readonly name: string
  readonly description: string
  readonly homepage?: string
  readonly documentation?: string
  readonly categories: string[]
  readonly tags: string[]
  readonly sources: string[]
  readonly aliases: string[]
  readonly curation: CurationState
  readonly lifecycle: Lifecycle
  readonly draft: boolean
  /**
   * At least one profile's auth shape is executable by this build. Whether a
   * call would actually go through is eligibility, which only `show`/`get_api`
   * report as `callable`.
   */
  readonly auth_supported: boolean
  readonly verification?: VerificationState
  readonly readiness: CredentialReadiness
  readonly health: HealthState
  readonly health_last_checked?: string
  readonly profile_count: number
  /** Set when the query text matched an alias rather than the canonical id. */
  readonly matched_alias?: string
  /** Set when the requested id was a merged record redirecting here. */
  readonly redirected_from?: string
  readonly score: number
  readonly exact: boolean
}

export interface Filters {
  curation?: CurationState
  lifecycle?: Lifecycle
  readiness?: CredentialReadiness
  auth_type?: AuthType
  health?: HealthState
  verification?: VerificationState
  source?: string
  category?: string
  tag?: string
}

export const FILTER_VOCABULARIES: Record<string, readonly string[]> = {
  curation: CURATION_STATES,
  lifecycle: LIFECYCLE_STATES,
  readiness: CREDENTIAL_READINESS,
  auth_type: AUTH_TYPES,
  health: HEALTH_STATES,
  verification: VERIFICATION_STATES,
}

/** Machine-local facts the catalog does not hold. */
export interface ProfileFacts {
  readonly readiness: CredentialReadiness
  readonly health: HealthState
  readonly lastChecked?: string
}

export interface FactsProvider {
  factsFor(apiId: string, profileId: string): ProfileFacts
}

/** Used before the credentials and health layers are attached. */
export const NEUTRAL_FACTS: FactsProvider = {
  factsFor: () => ({ readiness: 'no_grant', health: 'unknown' }),
}

interface ApiRow {
  id: string
  name: string
  description: string
  homepage: string | null
  documentation: string | null
  lifecycle: string
  curation: string
  merged_into: string | null
  categories: string
  tags: string
  sources: string
  draft: number
}

interface ProfileRow {
  api_id: string
  profile_id: string
  auth_type: string
  executable: number
  network_scope: string
  verification_state: string
  verified_at: string | null
  credential_id: string | null
  draft: number
}

const READINESS_PRECEDENCE: CredentialReadiness[] = [
  'ready',
  'not_required',
  'ambiguous_account',
  'missing_component',
  'fingerprint_mismatch',
  'no_grant',
  'unsupported_auth',
]

const HEALTH_PRECEDENCE: HealthState[] = [
  'healthy',
  'rate_limited',
  'auth_required',
  'degraded',
  'unreachable',
  'unknown',
]

function best<T>(order: readonly T[], values: readonly T[], fallback: T): T {
  for (const candidate of order) if (values.includes(candidate)) return candidate
  return fallback
}

/** Auth shape decides readiness before any local lookup does. */
function readinessOf(row: ProfileRow, facts: ProfileFacts): CredentialReadiness {
  if (row.auth_type === 'none') return 'not_required'
  if (row.executable !== 1) return 'unsupported_auth'
  return facts.readiness
}

function parseList(json: string): string[] {
  const parsed: unknown = JSON.parse(json)
  return Array.isArray(parsed)
    ? parsed.filter((item): item is string => typeof item === 'string')
    : []
}

export function validateFilters(filters: Record<string, string | undefined>): Filters {
  const out: Record<string, string> = {}
  for (const [name, value] of Object.entries(filters)) {
    if (value === undefined) continue
    const vocabulary = FILTER_VOCABULARIES[name]
    if (vocabulary && !vocabulary.includes(value)) {
      throw new ApimanacError(
        'usage',
        `\`${value}\` is not an allowed value for the \`${name}\` filter`,
        { filter: name, value, allowed: [...vocabulary] },
      )
    }
    out[name] = value
  }
  return out as Filters
}

export class CatalogQuery {
  constructor(
    private readonly db: Database,
    private readonly facts: FactsProvider = NEUTRAL_FACTS,
  ) {}

  private apis(): Map<string, ApiRow> {
    const rows = this.db
      .query<ApiRow, []>(
        'SELECT id, name, description, homepage, documentation, lifecycle, curation, merged_into, categories, tags, sources, draft FROM d_api ORDER BY id',
      )
      .all()
    return new Map(rows.map((row) => [row.id, row]))
  }

  private profilesByApi(): Map<string, ProfileRow[]> {
    const rows = this.db
      .query<ProfileRow, []>(
        'SELECT api_id, profile_id, auth_type, executable, network_scope, verification_state, verified_at, credential_id, draft FROM d_profile ORDER BY api_id, profile_id',
      )
      .all()
    const grouped = new Map<string, ProfileRow[]>()
    for (const row of rows) {
      const list = grouped.get(row.api_id) ?? []
      list.push(row)
      grouped.set(row.api_id, list)
    }
    return grouped
  }

  private aliasesByApi(): Map<string, string[]> {
    const rows = this.db
      .query<{ alias: string; api_id: string }, []>(
        'SELECT alias, api_id FROM d_alias ORDER BY api_id, alias',
      )
      .all()
    const grouped = new Map<string, string[]>()
    for (const row of rows) {
      const list = grouped.get(row.api_id) ?? []
      list.push(row.alias)
      grouped.set(row.api_id, list)
    }
    return grouped
  }

  /**
   * Profiles as the committed snapshot holds them. A query convenience only:
   * the live `HEAD` comparison in `evaluateEligibility` decides every call, and
   * a disagreement means the store is stale, not that a call is refused.
   */
  committedProfiles(apiId: string): { profile_id: string; verification: VerificationState }[] {
    return this.db
      .query<{ profile_id: string; verification_state: string }, [string]>(
        'SELECT profile_id, verification_state FROM a_profile WHERE api_id = ? ORDER BY profile_id',
      )
      .all(apiId)
      .map((row) => ({
        profile_id: row.profile_id,
        verification: row.verification_state as VerificationState,
      }))
  }

  /** Committed aliases, so identity questions can be answered without the worktree. */
  committedAliases(apiId: string): string[] {
    return this.db
      .query<{ alias: string }, [string]>(
        'SELECT alias FROM a_alias WHERE api_id = ? ORDER BY alias',
      )
      .all(apiId)
      .map((row) => row.alias)
  }

  profileSummaries(apiId: string): ProfileSummary[] {
    return (this.profilesByApi().get(apiId) ?? []).map((row) => this.summarize(row))
  }

  private summarize(row: ProfileRow): ProfileSummary {
    const facts = this.facts.factsFor(row.api_id, row.profile_id)

    return {
      profile_id: row.profile_id,
      auth_type: row.auth_type as AuthType,
      verification: row.verification_state as VerificationState,
      network_scope: row.network_scope,
      auth_supported: row.executable === 1,
      draft: row.draft === 1,
      readiness: readinessOf(row, facts),
      health: facts.health,
      health_last_checked: facts.lastChecked,
      verified_at: row.verified_at ?? undefined,
    }
  }

  /** Resolve an id or alias through the discovery projection. */
  resolve(requested: string): { id: string; alias?: string; redirectedFrom?: string } | undefined {
    const direct = this.db
      .query<{ id: string; lifecycle: string; merged_into: string | null }, [string]>(
        'SELECT id, lifecycle, merged_into FROM d_api WHERE id = ?',
      )
      .get(requested)
    if (direct) {
      if (direct.lifecycle !== 'merged') return { id: direct.id }
      // Walk the chain to its terminal target, guarding against a cycle the
      // catalog would have failed validation for.
      const seen = new Set<string>([direct.id])
      let current = direct
      while (current.lifecycle === 'merged' && current.merged_into) {
        if (seen.has(current.merged_into)) break
        seen.add(current.merged_into)
        const next = this.db
          .query<{ id: string; lifecycle: string; merged_into: string | null }, [string]>(
            'SELECT id, lifecycle, merged_into FROM d_api WHERE id = ?',
          )
          .get(current.merged_into)
        if (!next) return { id: current.merged_into, redirectedFrom: requested }
        current = next
      }
      return { id: current.id, redirectedFrom: requested }
    }
    const alias = this.db
      .query<{ api_id: string; kind: string }, [string]>(
        'SELECT api_id, kind FROM d_alias WHERE alias = ? ORDER BY kind DESC, api_id LIMIT 1',
      )
      .get(requested)
    if (!alias) return undefined
    return alias.kind === 'merge'
      ? { id: alias.api_id, redirectedFrom: requested }
      : { id: alias.api_id, alias: requested }
  }

  private buildResult(
    row: ApiRow,
    profiles: ProfileRow[],
    aliases: string[],
    lexical: number,
    exact: boolean,
    matched?: { alias?: string; redirectedFrom?: string },
  ): SearchResult {
    const summaries = profiles.map((profile) => this.summarize(profile))
    const readiness = summaries.length
      ? best(
          READINESS_PRECEDENCE,
          summaries.map((s) => s.readiness),
          'no_grant',
        )
      : 'not_required'
    const health = best(
      HEALTH_PRECEDENCE,
      summaries.map((s) => s.health),
      'unknown',
    )
    const lastChecked = summaries.find((s) => s.health === health)?.health_last_checked
    const verification: VerificationState | undefined = summaries.length
      ? summaries.some((s) => s.verification === 'verified')
        ? 'verified'
        : 'candidate'
      : undefined

    const boosts =
      (row.curation === 'curated' ? BOOSTS.curated : 0) +
      (verification === 'verified' ? BOOSTS.verified : 0) +
      (readiness === 'ready' || readiness === 'not_required' ? BOOSTS.ready : 0) +
      BOOSTS.health[health] +
      BOOSTS.lifecycle[row.lifecycle as Lifecycle] +
      (row.draft === 1 ? BOOSTS.draft : 0) +
      BOOST_FLOOR

    return {
      id: row.id,
      name: row.name,
      description: row.description,
      homepage: row.homepage ?? undefined,
      documentation: row.documentation ?? undefined,
      categories: parseList(row.categories),
      tags: parseList(row.tags),
      sources: parseList(row.sources),
      aliases,
      curation: row.curation as CurationState,
      lifecycle: row.lifecycle as Lifecycle,
      draft: row.draft === 1,
      auth_supported: summaries.some((s) => s.auth_supported),
      verification,
      readiness,
      health,
      health_last_checked: lastChecked,
      profile_count: summaries.length,
      matched_alias: matched?.alias,
      redirected_from: matched?.redirectedFrom,
      score: lexical + Math.max(0, boosts),
      exact,
    }
  }

  private matches(result: SearchResult, filters: Filters): boolean {
    if (filters.curation && result.curation !== filters.curation) return false
    if (filters.lifecycle && result.lifecycle !== filters.lifecycle) return false
    if (filters.readiness && result.readiness !== filters.readiness) return false
    if (filters.health && result.health !== filters.health) return false
    if (filters.verification && result.verification !== filters.verification) return false
    if (filters.source && !result.sources.includes(filters.source)) return false
    if (filters.category && !result.categories.includes(filters.category)) return false
    if (filters.tag && !result.tags.includes(filters.tag)) return false
    if (filters.auth_type) {
      const profiles = this.profileSummaries(result.id)
      if (!profiles.some((profile) => profile.auth_type === filters.auth_type)) return false
    }
    return true
  }

  search(
    queryText: string,
    options: { filters?: Filters; limit?: number } = {},
  ): { results: SearchResult[]; total: number; limit: number; more: boolean } {
    const filters = options.filters ?? {}
    const limit = Math.min(Math.max(1, options.limit ?? DEFAULT_LIMIT), MAX_LIMIT)
    const apis = this.apis()
    const profiles = this.profilesByApi()
    const aliases = this.aliasesByApi()

    const scored = new Map<string, SearchResult>()
    const text = queryText.trim()

    // An exact canonical id or alias short-circuits to the top of the results.
    const exact = text ? this.resolve(text) : undefined
    if (exact) {
      const row = apis.get(exact.id)
      if (row) {
        scored.set(
          exact.id,
          this.buildResult(
            row,
            profiles.get(exact.id) ?? [],
            aliases.get(exact.id) ?? [],
            0,
            true,
            { alias: exact.alias, redirectedFrom: exact.redirectedFrom },
          ),
        )
      }
    }

    if (text) {
      const weights = Object.values(COLUMN_WEIGHTS)
      const sql = `SELECT api_id, -bm25(fts_api, ${weights.join(', ')}) AS relevance
        FROM fts_api WHERE fts_api MATCH ? ORDER BY relevance DESC`
      let hits: { api_id: string; relevance: number }[] = []
      try {
        hits = this.db
          .query<{ api_id: string; relevance: number }, [string]>(sql)
          .all(ftsQuery(text))
      } catch {
        hits = []
      }
      for (const hit of hits) {
        if (scored.has(hit.api_id)) continue
        const row = apis.get(hit.api_id)
        if (!row) continue
        scored.set(
          hit.api_id,
          this.buildResult(
            row,
            profiles.get(hit.api_id) ?? [],
            aliases.get(hit.api_id) ?? [],
            hit.relevance,
            false,
          ),
        )
      }
    } else {
      for (const [id, row] of apis) {
        if (row.lifecycle === 'merged') continue
        scored.set(
          id,
          this.buildResult(row, profiles.get(id) ?? [], aliases.get(id) ?? [], 0, false),
        )
      }
    }

    const filtered = [...scored.values()].filter((result) => this.matches(result, filters))
    filtered.sort((a, b) => {
      if (a.exact !== b.exact) return a.exact ? -1 : 1
      if (a.score !== b.score) return b.score - a.score
      return a.id < b.id ? -1 : 1
    })

    return {
      results: filtered.slice(0, limit),
      total: filtered.length,
      limit,
      more: filtered.length > limit,
    }
  }
}

/** Turn free text into an FTS5 query of prefix-matched terms. */
export function ftsQuery(text: string): string {
  const terms = text
    .split(/[^\p{L}\p{N}]+/u)
    .filter((term) => term.length > 0)
    .map((term) => `"${term.replace(/"/g, '""')}"*`)
  return terms.length ? terms.join(' OR ') : '""'
}
