import type { Database } from 'bun:sqlite'

/**
 * The derived store. Discovery tables (`d_*`) come from working-tree YAML and
 * carry draft labels; authority tables (`a_*`) come from `HEAD` blobs. The
 * `meta` table records what the build consumed, so staleness is detectable
 * without re-reading the catalog.
 */

export const BUILDER_VERSION = '1'

const COMMON_COLUMNS = `
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  homepage TEXT,
  documentation TEXT,
  lifecycle TEXT NOT NULL,
  curation TEXT NOT NULL,
  merged_into TEXT,
  categories TEXT NOT NULL DEFAULT '[]',
  tags TEXT NOT NULL DEFAULT '[]',
  sources TEXT NOT NULL DEFAULT '[]',
  capabilities TEXT NOT NULL DEFAULT '[]',
  spec_summary TEXT NOT NULL DEFAULT '[]',
  file TEXT NOT NULL,
  state TEXT NOT NULL
`

const PROFILE_COLUMNS = `
  api_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  origins TEXT NOT NULL,
  base_path TEXT,
  auth_type TEXT NOT NULL,
  credential_id TEXT,
  components TEXT NOT NULL DEFAULT '[]',
  executable INTEGER NOT NULL,
  network_scope TEXT NOT NULL,
  verification_state TEXT NOT NULL,
  verified_at TEXT,
  contract_hash TEXT NOT NULL,
  authority_fingerprint TEXT NOT NULL,
  cache_enabled INTEGER NOT NULL,
  allowed_headers TEXT NOT NULL DEFAULT '[]',
  spec_ref TEXT,
  file TEXT NOT NULL,
  state TEXT NOT NULL
`

const PROFILE_PRIMARY_KEY = ', PRIMARY KEY (api_id, profile_id)'

const OPERATION_COLUMNS = `
  api_id TEXT NOT NULL,
  profile_id TEXT NOT NULL,
  method TEXT NOT NULL,
  path TEXT NOT NULL,
  decision TEXT NOT NULL,
  note TEXT
`

export function applySchema(db: Database): void {
  db.run('PRAGMA journal_mode = WAL')
  db.run('PRAGMA foreign_keys = ON')
  db.run('CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)')

  db.run(`CREATE TABLE d_api (${COMMON_COLUMNS}, draft INTEGER NOT NULL)`)
  db.run(`CREATE TABLE a_api (${COMMON_COLUMNS})`)

  db.run(
    'CREATE TABLE d_alias (alias TEXT NOT NULL, api_id TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY (alias, api_id))',
  )
  db.run(
    'CREATE TABLE a_alias (alias TEXT NOT NULL, api_id TEXT NOT NULL, kind TEXT NOT NULL, PRIMARY KEY (alias, api_id))',
  )

  db.run(
    `CREATE TABLE d_profile (${PROFILE_COLUMNS}, draft INTEGER NOT NULL${PROFILE_PRIMARY_KEY})`,
  )
  db.run(`CREATE TABLE a_profile (${PROFILE_COLUMNS}${PROFILE_PRIMARY_KEY})`)

  db.run(`CREATE TABLE d_operation (${OPERATION_COLUMNS})`)
  db.run(`CREATE TABLE a_operation (${OPERATION_COLUMNS})`)

  db.run('CREATE INDEX d_profile_api ON d_profile (api_id)')
  db.run('CREATE INDEX a_profile_api ON a_profile (api_id)')
  db.run('CREATE INDEX d_operation_profile ON d_operation (api_id, profile_id)')
  db.run('CREATE INDEX a_operation_profile ON a_operation (api_id, profile_id)')
  db.run('CREATE INDEX d_alias_target ON d_alias (api_id)')

  // A content-carrying FTS table: the canonical id is UNINDEXED but readable,
  // so every hit joins back to its record.
  db.run(`CREATE VIRTUAL TABLE fts_api USING fts5(
    api_id UNINDEXED,
    name,
    aliases,
    description,
    categories,
    tags,
    provenance,
    capabilities,
    tokenize = 'unicode61 remove_diacritics 2'
  )`)
}

export function readMeta(db: Database, key: string): string | undefined {
  const row = db.query<{ value: string }, [string]>('SELECT value FROM meta WHERE key = ?').get(key)
  return row?.value
}

export function writeMeta(db: Database, key: string, value: string): void {
  db.run('INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)', [key, value])
}
