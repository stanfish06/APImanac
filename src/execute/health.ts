import { Database } from 'bun:sqlite'
import { mkdirSync } from 'node:fs'
import { dirname } from 'node:path'
import { LIMITS } from '../policy/limits'
import { paths } from '../paths'
import type { HealthState } from '../schema/vocab'

/**
 * Machine-local health observations. Nothing here writes tracked YAML, and no
 * observation changes a record's lifecycle — only a reviewed metadata change
 * sets `gone`.
 */

export interface Observation {
  readonly status?: number
  readonly retryAfter?: boolean
  readonly transportFailure?: 'dns' | 'connection' | 'tls' | 'timeout'
  readonly redirectRefused?: boolean
  /** The status a profile's probe declares, when this observation is a probe. */
  readonly expectedStatus?: number
}

/** The closed status table. Every observation maps to exactly one state. */
export function classifyObservation(observation: Observation): HealthState {
  if (observation.transportFailure) return 'unreachable'
  if (observation.redirectRefused) return 'degraded'
  const status = observation.status
  if (status === undefined) return 'unknown'
  if (observation.expectedStatus !== undefined && status === observation.expectedStatus) {
    return 'healthy'
  }
  if (status >= 200 && status < 300) return 'healthy'
  if (status >= 300 && status < 400) return 'healthy'
  if (status === 401 || status === 403 || status === 407) return 'auth_required'
  if (status === 429) return 'rate_limited'
  if (status === 503) return observation.retryAfter ? 'rate_limited' : 'degraded'
  return 'degraded'
}

export interface HealthRecord {
  readonly api_id: string
  readonly profile_id: string
  readonly state: HealthState
  readonly last_checked: string
}

export class HealthStore {
  private constructor(private readonly db: Database) {}

  static open(path: string = paths.healthDb()): HealthStore {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 })
    const db = new Database(path, { create: true })
    db.run(`CREATE TABLE IF NOT EXISTS observation (
      api_id TEXT NOT NULL,
      profile_id TEXT NOT NULL,
      state TEXT NOT NULL,
      observed_at TEXT NOT NULL,
      sequence INTEGER PRIMARY KEY AUTOINCREMENT
    )`)
    db.run('CREATE INDEX IF NOT EXISTS observation_profile ON observation (api_id, profile_id)')
    return new HealthStore(db)
  }

  /** Last-write-wins: the most recent observation is the reported state. */
  record(
    apiId: string,
    profileId: string,
    observation: Observation,
    at: Date = new Date(),
  ): HealthRecord {
    const state = classifyObservation(observation)
    const timestamp = at.toISOString()
    this.db.run(
      'INSERT INTO observation (api_id, profile_id, state, observed_at) VALUES (?, ?, ?, ?)',
      [apiId, profileId, state, timestamp],
    )
    this.db.run(
      `DELETE FROM observation WHERE api_id = ? AND profile_id = ? AND sequence NOT IN (
         SELECT sequence FROM observation WHERE api_id = ? AND profile_id = ?
         ORDER BY sequence DESC LIMIT ?
       )`,
      [apiId, profileId, apiId, profileId, LIMITS.healthObservationsPerProfile],
    )
    return { api_id: apiId, profile_id: profileId, state, last_checked: timestamp }
  }

  /** `unknown` when no observation is retained, reported rather than omitted. */
  stateOf(apiId: string, profileId: string): HealthRecord {
    const row = this.db
      .query<{ state: string; observed_at: string }, [string, string]>(
        'SELECT state, observed_at FROM observation WHERE api_id = ? AND profile_id = ? ORDER BY sequence DESC LIMIT 1',
      )
      .get(apiId, profileId)
    return {
      api_id: apiId,
      profile_id: profileId,
      state: (row?.state as HealthState) ?? 'unknown',
      last_checked: row?.observed_at ?? '',
    }
  }

  count(apiId: string, profileId: string): number {
    return (
      this.db
        .query<{ n: number }, [string, string]>(
          'SELECT COUNT(*) AS n FROM observation WHERE api_id = ? AND profile_id = ?',
        )
        .get(apiId, profileId)?.n ?? 0
    )
  }

  close(): void {
    this.db.close()
  }
}
