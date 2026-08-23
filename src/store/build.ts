import { Database } from 'bun:sqlite'
import { createHash } from 'node:crypto'
import { existsSync, mkdirSync, readFileSync, renameSync, rmSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { authorityFingerprint, contractHash } from '../catalog/canonical'
import { buildIdentityIndex } from '../catalog/identity'
import type { CatalogSnapshot, LoadedFile } from '../catalog/load'
import { loadCommitted, loadWorkingTree } from '../catalog/load'
import type { CatalogRoot } from '../catalog/root'
import { validateCatalog } from '../catalog/validate'
import { ApimanacError } from '../errors'
import type { ExecutionProfile } from '../schema/execution'
import type { MetadataRecord } from '../schema/metadata'
import { isExecutableAuthType } from '../schema/vocab'
import { BUILDER_VERSION, applySchema, writeMeta } from './schema'

/**
 * Deterministic, network-free build. The store is written to a temp file and
 * renamed into place, so a failed or interrupted build leaves the previous
 * store usable and a rebuilt index has no history to accumulate stale rows in.
 */

export const INPUT_HASH_KEY = 'input_hash'
export const HEAD_KEY = 'head_commit'
export const BUILDER_KEY = 'builder_version'

/**
 * Covers both the working-tree catalog bytes and the resolved `HEAD` commit, so
 * committing a pending change makes the store stale even when no worktree byte
 * moved.
 */
export function canonicalInputHash(root: CatalogRoot): string {
  const hash = createHash('sha256')
  hash.update(`builder:${BUILDER_VERSION}\n`)
  hash.update(`head:${root.git.head ?? 'none'}\n`)
  const files = catalogFiles(root.path)
  for (const file of files) {
    hash.update(file)
    hash.update('\0')
    hash.update(
      createHash('sha256')
        .update(readFileSync(join(root.path, file)))
        .digest('hex'),
    )
    hash.update('\n')
  }
  return `v1:sha256:${hash.digest('hex')}`
}

function catalogFiles(catalogRoot: string): string[] {
  const glob = new Bun.Glob('catalog/**/*.yaml')
  return [...glob.scanSync({ cwd: catalogRoot, onlyFiles: true, dot: false })].sort()
}

interface ProfileRow {
  api_id: string
  profile_id: string
  description: string
  origins: string
  base_path: string | null
  auth_type: string
  credential_id: string | null
  components: string
  executable: number
  network_scope: string
  verification_state: string
  verified_at: string | null
  contract_hash: string
  authority_fingerprint: string
  cache_enabled: number
  allowed_headers: string
  spec_ref: string | null
  file: string
  state: string
}

function profileRow(entry: LoadedFile<ExecutionProfile>): ProfileRow {
  const profile = entry.value
  return {
    api_id: profile.api_id,
    profile_id: profile.profile_id,
    description: profile.description,
    origins: JSON.stringify(profile.origins),
    base_path: profile.base_path ?? null,
    auth_type: profile.auth.type,
    credential_id: profile.auth.credential_id ?? null,
    components: JSON.stringify(profile.auth.components.map((component) => component.name)),
    executable: isExecutableAuthType(profile.auth.type) ? 1 : 0,
    network_scope: profile.network_scope,
    verification_state: profile.verification.state,
    verified_at: profile.verification.verified_at ?? null,
    contract_hash: contractHash(profile),
    authority_fingerprint: authorityFingerprint(profile),
    cache_enabled: profile.cache.enabled ? 1 : 0,
    allowed_headers: JSON.stringify(profile.response.allowed_headers),
    spec_ref: profile.spec_ref ? JSON.stringify(profile.spec_ref) : null,
    file: entry.file,
    state: entry.state,
  }
}

function apiValues(entry: LoadedFile<MetadataRecord>): unknown[] {
  const record = entry.value
  return [
    record.id,
    record.name,
    record.description,
    record.homepage ?? null,
    record.documentation ?? null,
    record.lifecycle,
    record.curation,
    record.merged_into ?? null,
    JSON.stringify(record.categories),
    JSON.stringify(record.tags),
    JSON.stringify(record.sources),
    JSON.stringify(record.capabilities),
    JSON.stringify(record.specs.map((spec) => ({ id: spec.id, summary: spec.summary ?? '' }))),
    entry.file,
    entry.state,
  ]
}

const API_COLUMNS =
  'id, name, description, homepage, documentation, lifecycle, curation, merged_into, categories, tags, sources, capabilities, spec_summary, file, state'

const PROFILE_INSERT_COLUMNS = [
  'api_id',
  'profile_id',
  'description',
  'origins',
  'base_path',
  'auth_type',
  'credential_id',
  'components',
  'executable',
  'network_scope',
  'verification_state',
  'verified_at',
  'contract_hash',
  'authority_fingerprint',
  'cache_enabled',
  'allowed_headers',
  'spec_ref',
  'file',
  'state',
] as const

function populate(db: Database, snapshot: CatalogSnapshot, prefix: 'd' | 'a'): void {
  // Merge chains terminate at a non-merged record; the store records that
  // target so a search hit resolves the same way identity does.
  const index = buildIdentityIndex(snapshot.records)
  const draftColumn = prefix === 'd' ? ', draft' : ''
  const draftValue = prefix === 'd' ? ', ?' : ''
  const apiInsert = db.prepare(
    `INSERT INTO ${prefix}_api (${API_COLUMNS}${draftColumn}) VALUES (${'?, '.repeat(15).slice(0, -2)}${draftValue})`,
  )
  const aliasInsert = db.prepare(
    `INSERT OR IGNORE INTO ${prefix}_alias (alias, api_id, kind) VALUES (?, ?, ?)`,
  )
  const profileInsert = db.prepare(
    `INSERT INTO ${prefix}_profile (${PROFILE_INSERT_COLUMNS.join(', ')}${draftColumn}) VALUES (${'?, '.repeat(PROFILE_INSERT_COLUMNS.length).slice(0, -2)}${draftValue})`,
  )
  const operationInsert = db.prepare(
    `INSERT INTO ${prefix}_operation (api_id, profile_id, method, path, decision, note) VALUES (?, ?, ?, ?, ?, ?)`,
  )

  // Sorted so two builds over the same catalog write identical row order.
  const records = [...snapshot.records.values()].sort((a, b) => (a.value.id < b.value.id ? -1 : 1))
  for (const entry of records) {
    const values = apiValues(entry)
    apiInsert.run(...((prefix === 'd' ? [...values, entry.draft ? 1 : 0] : values) as never[]))
    for (const alias of [...entry.value.aliases].sort()) {
      aliasInsert.run(alias, entry.value.id, 'alias')
    }
    if (entry.value.lifecycle === 'merged' && entry.value.merged_into) {
      const target = index.resolve(entry.value.id)?.id ?? entry.value.merged_into
      aliasInsert.run(entry.value.id, target, 'merge')
      for (const alias of entry.value.aliases) {
        aliasInsert.run(alias, target, 'merge')
      }
    }
  }

  const profiles = [...snapshot.profiles.values()].sort((a, b) => (a.file < b.file ? -1 : 1))
  for (const entry of profiles) {
    const row = profileRow(entry)
    const values = PROFILE_INSERT_COLUMNS.map((column) => row[column])
    profileInsert.run(...((prefix === 'd' ? [...values, entry.draft ? 1 : 0] : values) as never[]))
    for (const rule of entry.value.permissions) {
      operationInsert.run(
        row.api_id,
        row.profile_id,
        rule.method,
        rule.path,
        rule.decision,
        rule.note ?? null,
      )
    }
  }
}

function populateIndex(db: Database, snapshot: CatalogSnapshot): void {
  const index = buildIdentityIndex(snapshot.records)
  const insert = db.prepare(
    'INSERT INTO fts_api (api_id, name, aliases, description, categories, tags, provenance, capabilities) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
  )
  const records = [...snapshot.records.values()].sort((a, b) => (a.value.id < b.value.id ? -1 : 1))
  for (const entry of records) {
    const record = entry.value
    // A merged record is reachable through its target's aliases, never as its own hit.
    if (record.lifecycle === 'merged') continue
    const profileSummaries = [...snapshot.profiles.values()]
      .filter((profile) => profile.value.api_id === record.id)
      .flatMap((profile) => [
        profile.value.profile_id,
        profile.value.description,
        ...profile.value.origins,
        ...profile.value.permissions.map((rule) => rule.path),
      ])
    insert.run(
      record.id,
      `${record.name} ${record.id}`,
      index.aliasesOf(record.id).join(' '),
      record.description,
      record.categories.join(' '),
      record.tags.join(' '),
      [...record.sources, ...Object.values(record.provenance).map((p) => p.source)].join(' '),
      [
        ...record.capabilities,
        ...profileSummaries,
        ...record.specs.map((s) => s.summary ?? ''),
      ].join(' '),
    )
  }
}

export interface BuildResult {
  readonly path: string
  readonly inputHash: string
  readonly head?: string
  readonly discoveryRecords: number
  readonly authorityRecords: number
  readonly indexRows: number
}

export interface BuildOptions {
  readonly storePath: string
  /** Skip validation refusal; used only where a caller already validated. */
  readonly skipValidation?: boolean
}

export function buildStore(root: CatalogRoot, options: BuildOptions): BuildResult {
  const working = loadWorkingTree(root.path, root.git)
  if (!options.skipValidation) {
    const report = validateCatalog(working)
    if (!report.ok) {
      throw new ApimanacError(
        'validation_failed',
        'the catalog does not validate, so it was not built',
        {
          findings: report.findings,
        },
      )
    }
  }
  const committed = loadCommitted(root.git)

  mkdirSync(dirname(options.storePath), { recursive: true })
  const temporary = `${options.storePath}.tmp-${process.pid}`
  rmSync(temporary, { force: true })
  rmSync(`${temporary}-wal`, { force: true })
  rmSync(`${temporary}-shm`, { force: true })

  const inputHash = canonicalInputHash(root)
  let result: BuildResult
  const db = new Database(temporary, { create: true })
  try {
    applySchema(db)
    db.transaction(() => {
      populate(db, working, 'd')
      if (root.git.available) populate(db, committed, 'a')
      populateIndex(db, working)
      writeMeta(db, INPUT_HASH_KEY, inputHash)
      writeMeta(db, HEAD_KEY, root.git.head ?? '')
      writeMeta(db, BUILDER_KEY, BUILDER_VERSION)
      writeMeta(db, 'catalog_root', root.path)
    })()
    const count = (table: string): number =>
      db.query<{ n: number }, []>(`SELECT COUNT(*) AS n FROM ${table}`).get()?.n ?? 0
    result = {
      path: options.storePath,
      inputHash,
      head: root.git.head,
      discoveryRecords: count('d_api'),
      authorityRecords: count('a_api'),
      indexRows: count('fts_api'),
    }
    // WAL frames must land in the file before it is renamed into place.
    db.run('PRAGMA wal_checkpoint(TRUNCATE)')
  } finally {
    db.close()
  }

  rmSync(`${temporary}-wal`, { force: true })
  rmSync(`${temporary}-shm`, { force: true })
  rmSync(`${options.storePath}-wal`, { force: true })
  rmSync(`${options.storePath}-shm`, { force: true })
  // Atomic replacement: the previous store stays queryable until this instant.
  renameSync(temporary, options.storePath)
  return result
}

export function storeExists(storePath: string): boolean {
  return existsSync(storePath)
}
