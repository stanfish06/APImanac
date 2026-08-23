import { Database } from 'bun:sqlite'
import { createHash, createHmac, randomBytes } from 'node:crypto'
import {
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs'
import { join } from 'node:path'
import { LIMITS } from '../policy/limits'
import { paths } from '../paths'
import type { SanitizedRequest } from './sanitize'

/**
 * Response cache. Identity is an HMAC over the canonical request tuple keyed by
 * a machine-local random key, so no authenticated URL, raw header, or credential
 * query value is ever persisted. The quota is enforced on the write path rather
 * than depending on `prune` being run.
 */

const IDEMPOTENT_METHODS = new Set(['GET', 'HEAD'])

export interface CacheOptions {
  readonly directory?: string
  readonly quotaBytes?: number
  readonly now?: () => number
}

export interface CacheEntryLabels {
  readonly key: string
  readonly origin: string
  readonly path: string
  readonly account?: string
  readonly profile: string
  readonly bytes: number
  readonly stored_at: string
  readonly expires_at: string
}

export interface CachedResponse {
  readonly status: number
  readonly headers: Record<string, string>
  readonly body: Buffer
}

export class ResponseCache {
  private constructor(
    private readonly db: Database,
    private readonly directory: string,
    private readonly key: Buffer,
    private readonly quota: number,
    private readonly now: () => number,
  ) {}

  static open(options: CacheOptions = {}): ResponseCache {
    const directory = options.directory ?? paths.responseCacheDir()
    mkdirSync(directory, { recursive: true, mode: 0o700 })
    const keyPath = join(directory, 'cache.key')
    let key: Buffer
    if (existsSync(keyPath)) {
      key = readFileSync(keyPath)
    } else {
      key = randomBytes(32)
      writeFileSync(keyPath, key, { mode: 0o600 })
    }
    chmodSync(keyPath, 0o600)
    const db = new Database(join(directory, 'index.db'), { create: true })
    db.run(`CREATE TABLE IF NOT EXISTS entry (
      key TEXT PRIMARY KEY,
      profile TEXT NOT NULL,
      origin TEXT NOT NULL,
      path TEXT NOT NULL,
      account TEXT,
      status INTEGER NOT NULL,
      headers TEXT NOT NULL,
      bytes INTEGER NOT NULL,
      stored_at INTEGER NOT NULL,
      expires_at INTEGER NOT NULL,
      last_access INTEGER NOT NULL
    )`)
    return new ResponseCache(
      db,
      directory,
      key,
      options.quotaBytes ?? LIMITS.cacheQuotaBytes,
      options.now ?? (() => Date.now()),
    )
  }

  /**
   * Cache identity: profile, contract hash, a keyed account discriminator, the
   * method, the canonical origin and path with non-credential query parameters,
   * keyed digests of credential query values and representation headers, and
   * the canonical body hash.
   */
  identity(
    request: SanitizedRequest,
    contractHash: string,
    credentialQueryValues: readonly string[] = [],
    representationHeaders: readonly (readonly [string, string])[] = [],
  ): string {
    const keyed = (value: string): string =>
      createHmac('sha256', this.key).update(value).digest('hex')
    const tuple = JSON.stringify({
      profile: `${request.api_id}/${request.profile_id}`,
      contract_hash: contractHash,
      account: keyed(`account:${request.account ?? ''}`),
      method: request.method,
      origin: request.origin,
      path: request.path,
      query: request.query,
      credential_query: credentialQueryValues.map((value) => keyed(`q:${value}`)).sort(),
      representation: representationHeaders
        .map(([name, value]) => `${name.toLowerCase()}:${keyed(`h:${value}`)}`)
        .sort(),
      body: request.body?.hash ?? null,
    })
    return createHmac('sha256', this.key).update(tuple).digest('hex')
  }

  private bodyPath(key: string): string {
    return join(this.directory, `${key}.body`)
  }

  read(key: string): CachedResponse | undefined {
    const row = this.db
      .query<{ status: number; headers: string; expires_at: number }, [string]>(
        'SELECT status, headers, expires_at FROM entry WHERE key = ?',
      )
      .get(key)
    if (!row) return undefined
    if (row.expires_at <= this.now()) return undefined
    const path = this.bodyPath(key)
    if (!existsSync(path)) return undefined
    this.db.run('UPDATE entry SET last_access = ? WHERE key = ?', [this.now(), key])
    return {
      status: row.status,
      headers: JSON.parse(row.headers) as Record<string, string>,
      body: readFileSync(path),
    }
  }

  /** Non-idempotent operations are never cached unless the profile enables it. */
  static cacheable(method: string, allowMutations: boolean): boolean {
    return IDEMPOTENT_METHODS.has(method.toUpperCase()) || allowMutations
  }

  write(
    key: string,
    request: SanitizedRequest,
    response: CachedResponse,
    ttlSeconds: number,
  ): boolean {
    const bytes = response.body.byteLength
    // A response larger than the whole quota is not cached, and evicts nothing.
    if (bytes > this.quota) return false
    this.evictFor(bytes, key)
    writeFileSync(this.bodyPath(key), response.body, { mode: 0o600 })
    const now = this.now()
    this.db.run(
      `INSERT OR REPLACE INTO entry
       (key, profile, origin, path, account, status, headers, bytes, stored_at, expires_at, last_access)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        key,
        `${request.api_id}/${request.profile_id}`,
        request.origin,
        request.path,
        request.account ?? null,
        response.status,
        JSON.stringify(response.headers),
        bytes,
        now,
        now + ttlSeconds * 1000,
        now,
      ],
    )
    return true
  }

  private totalBytes(): number {
    return (
      this.db.query<{ n: number }, []>('SELECT COALESCE(SUM(bytes), 0) AS n FROM entry').get()?.n ??
      0
    )
  }

  /** Evict least-recently-used entries until the new entry fits. */
  private evictFor(bytes: number, replacing: string): void {
    const existing = this.db
      .query<{ bytes: number }, [string]>('SELECT bytes FROM entry WHERE key = ?')
      .get(replacing)
    let total = this.totalBytes() - (existing?.bytes ?? 0)
    if (total + bytes <= this.quota) return
    const candidates = this.db
      .query<{ key: string; bytes: number }, [string]>(
        'SELECT key, bytes FROM entry WHERE key != ? ORDER BY last_access ASC',
      )
      .all(replacing)
    for (const candidate of candidates) {
      this.delete(candidate.key)
      total -= candidate.bytes
      if (total + bytes <= this.quota) return
    }
  }

  delete(key: string): void {
    rmSync(this.bodyPath(key), { force: true })
    this.db.run('DELETE FROM entry WHERE key = ?', [key])
  }

  /** Sanitized labels only: origin, path, and account. */
  list(): CacheEntryLabels[] {
    return this.db
      .query<
        {
          key: string
          profile: string
          origin: string
          path: string
          account: string | null
          bytes: number
          stored_at: number
          expires_at: number
        },
        []
      >(
        'SELECT key, profile, origin, path, account, bytes, stored_at, expires_at FROM entry ORDER BY last_access DESC',
      )
      .all()
      .map((row) => ({
        key: row.key,
        profile: row.profile,
        origin: row.origin,
        path: row.path,
        account: row.account ?? undefined,
        bytes: row.bytes,
        stored_at: new Date(row.stored_at).toISOString(),
        expires_at: new Date(row.expires_at).toISOString(),
      }))
  }

  clear(): number {
    const keys = this.db.query<{ key: string }, []>('SELECT key FROM entry').all()
    for (const row of keys) this.delete(row.key)
    return keys.length
  }

  /** Removes expired entries and may shrink the store to quota. */
  prune(): { expired: number; evicted: number; bytes: number } {
    const now = this.now()
    const expired = this.db
      .query<{ key: string }, [number]>('SELECT key FROM entry WHERE expires_at <= ?')
      .all(now)
    for (const row of expired) this.delete(row.key)
    let evicted = 0
    while (this.totalBytes() > this.quota) {
      const oldest = this.db
        .query<{ key: string }, []>('SELECT key FROM entry ORDER BY last_access ASC LIMIT 1')
        .get()
      if (!oldest) break
      this.delete(oldest.key)
      evicted += 1
    }
    return { expired: expired.length, evicted, bytes: this.totalBytes() }
  }

  get bytes(): number {
    return this.totalBytes()
  }

  keyFileMode(): number {
    return statSync(join(this.directory, 'cache.key')).mode & 0o777
  }

  close(): void {
    this.db.close()
  }
}

/** Digest used where a body hash is required for a cached response. */
export function bodyDigest(body: Buffer): string {
  return `v1:sha256:${createHash('sha256').update(body).digest('hex')}`
}
