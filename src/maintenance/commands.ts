import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { parse, stringify } from 'yaml'
import { z } from 'zod'
import { buildIdentityIndex } from '../catalog/identity'
import {
  EXECUTION_DIR,
  MANIFEST_PATH,
  META_DIR,
  type CatalogSnapshot,
  loadWorkingTree,
  metadataPath,
  profilePath,
} from '../catalog/load'
import { applyFieldUpdates, planFieldUpdates, type FieldConflict } from '../catalog/provenance'
import type { CatalogRoot } from '../catalog/root'
import { validateCatalog } from '../catalog/validate'
import { MUTATING_METHODS } from '../policy/permissions'
import { ApimanacError } from '../errors'
import { RootManifest, SUPPORTED_SCHEMA_VERSION } from '../schema/manifest'
import { CanonicalId } from '../schema/vocab'
import { MetadataRecord, type SourceOwnedField } from '../schema/metadata'
import { ExecutionProfile } from '../schema/execution'
import { applyAdapterRun, type ApplyReport } from './apply'
import { externalExtractor, maintenanceFetch } from './fetch'
import { extractLocal, extractOpenApi, slugify, type Extraction } from './extract'
import type { AdapterRun, SourcePin } from '../ingest/adapter'
import { runApisGuru } from '../ingest/apis-guru'
import { runNango } from '../ingest/nango'
import { runPublicApis } from '../ingest/public-apis'

/**
 * Catalog maintenance. Every command leaves an uncommitted worktree diff:
 * nothing here stages, commits, pushes, or merges, and nothing verifies a
 * profile or activates a credential.
 */

interface Argvish {
  readonly positional: string[]
  readonly flags: Record<string, string | boolean | string[]>
}

interface Io {
  out(text: string): void
  err(text: string): void
}

function flag(argv: Argvish, name: string): string | undefined {
  const value = argv.flags[name]
  return typeof value === 'string' ? value : undefined
}

function writeYaml(root: CatalogRoot, relative: string, value: unknown): void {
  const absolute = join(root.path, relative)
  mkdirSync(dirname(absolute), { recursive: true })
  writeFileSync(absolute, stringify(value))
}

export interface AddResult {
  readonly ok: boolean
  readonly api_id?: string
  readonly extraction_method?: string
  readonly source_url?: string
  readonly retrieved_at?: string
  readonly files: string[]
  readonly message: string
}

export async function runAdd(
  root: CatalogRoot,
  argv: Argvish,
  io: Io,
  json: boolean,
): Promise<unknown> {
  const manual = argv.flags.manual === true || argv.flags.manual === 'true'
  const result = manual ? addManual(root, argv) : await addFromUrl(root, argv)
  if (json) return result
  if (!result.ok) throw new ApimanacError('policy_refused', result.message, { files: result.files })
  io.out(result.message)
  for (const file of result.files) io.out(`  wrote ${file} (uncommitted)`)
  return undefined
}

/**
 * Refuse to write over an identity the catalog already holds. `add` proposes a
 * new record; replacing a curated one is a reviewer's edit, not an import.
 */
function assertIdentityFree(root: CatalogRoot, id: string, force: boolean): void {
  if (force) return
  const snapshot = loadWorkingTree(root.path, root.git)
  const existing = snapshot.records.get(id)
  if (existing) {
    throw new ApimanacError(
      'usage',
      `\`${id}\` already exists at ${existing.file}; edit it directly, or pass --force to overwrite`,
      { api_id: id, file: existing.file },
    )
  }
  const claimed = buildIdentityIndex(snapshot.records).resolve(id)
  if (claimed) {
    throw new ApimanacError(
      'usage',
      `\`${id}\` already resolves to \`${claimed.id}\`; choose another --id, or pass --force`,
      { api_id: id, resolves_to: claimed.id },
    )
  }
}

function addManual(root: CatalogRoot, argv: Argvish): AddResult {
  const id = flag(argv, 'id') ?? slugify(argv.positional[0] ?? '')
  if (!id) {
    throw new ApimanacError('usage', 'add --manual needs --id <canonical-id> or a name to slugify')
  }
  assertIdentityFree(root, id, argv.flags.force === true)
  const name = flag(argv, 'name') ?? argv.positional[0] ?? id
  const record = MetadataRecord.parse({
    id,
    name,
    description: flag(argv, 'description') ?? '',
    curation: 'curated',
    sources: ['manual'],
    provenance: { name: { source: 'manual', last_observed: name, curated: true } },
    // A manual record has no URL requirement and no execution profile.
    profiles: [],
  })
  const file = metadataPath(id)
  writeYaml(root, file, record)
  return {
    ok: true,
    api_id: id,
    extraction_method: 'manual',
    files: [file],
    message: `wrote ${file} with manual provenance and no execution profile`,
  }
}

async function addFromUrl(root: CatalogRoot, argv: Argvish): Promise<AddResult> {
  const url = argv.positional[0]
  if (!url) throw new ApimanacError('usage', 'add needs a URL, or --manual')

  const fetched = await maintenanceFetch(url)
  if (!fetched.ok || !fetched.bytes) {
    return {
      ok: false,
      source_url: url,
      retrieved_at: fetched.retrievedAt,
      files: [],
      message: fetched.message ?? `could not retrieve ${url}`,
    }
  }

  // Ordered attempts: OpenAPI parse, local extraction, then the optional
  // external extractor, which is unconfigured by default.
  let extraction: Extraction | undefined =
    extractOpenApi(fetched.bytes, url) ?? extractLocal(fetched.bytes, url)
  if (!extraction) {
    const provider = externalExtractor()
    if (!provider) {
      return {
        ok: false,
        source_url: url,
        retrieved_at: fetched.retrievedAt,
        files: [],
        message:
          'local extraction failed and no external extractor is configured, so nothing was written',
      }
    }
    const extracted = await provider.extract(url)
    if (!extracted?.name) {
      return {
        ok: false,
        source_url: url,
        retrieved_at: fetched.retrievedAt,
        files: [],
        message: `the external extractor \`${provider.name}\` produced nothing, so nothing was written`,
      }
    }
    extraction = {
      method: 'external',
      name: extracted.name,
      description: extracted.description ?? '',
      documentation: url,
      categories: [],
      tags: [],
      origins: [],
      operations: [],
    }
  }

  const id = flag(argv, 'id') ?? slugify(extraction.name)
  if (!id) {
    throw new ApimanacError(
      'usage',
      `\`${extraction.name}\` does not slugify to a canonical id; pass --id`,
    )
  }

  assertIdentityFree(root, id, argv.flags.force === true)
  const provenanceNote = `${extraction.method} from ${url} at ${fetched.retrievedAt}`
  const record = MetadataRecord.parse({
    id,
    name: extraction.name,
    description: extraction.description,
    documentation: extraction.documentation,
    categories: extraction.categories,
    tags: extraction.tags,
    curation: 'imported',
    sources: ['manual'],
    provenance: {
      name: { source: 'manual', last_observed: extraction.name },
      description: { source: 'manual', last_observed: extraction.description },
      documentation: { source: 'manual', last_observed: provenanceNote },
    },
    profiles: extraction.origins.length ? ['candidate'] : [],
  })
  // Both documents parse before either is written, so a schema failure on the
  // profile cannot leave a half-written add behind.
  const pending: { file: string; value: unknown }[] = [{ file: metadataPath(id), value: record }]

  if (extraction.origins.length) {
    const profile = ExecutionProfile.parse({
      profile_id: 'candidate',
      api_id: id,
      description: `Derived from the specification at ${url}`,
      origins: extraction.origins,
      base_path: extraction.basePath,
      auth: { type: 'none' },
      permissions: [
        ...extraction.operations.slice(0, 50).map((operation) => ({
          method: operation.method,
          path: operation.path,
          decision: 'auto',
        })),
        // Denying `*` would also deny the read rules above; unmatched
        // operations already default to `confirm`.
        ...MUTATING_METHODS.map((method) => ({ method, path: '/**', decision: 'deny' })),
      ],
      spec_ref: {
        id: 'imported',
        url,
        format: extraction.specFormat,
        byte_size: extraction.specByteSize,
        summary: extraction.description.slice(0, 2000),
      },
      // `add` never verifies a profile.
      verification: { state: 'candidate' },
    })
    pending.push({ file: profilePath(id, 'candidate'), value: profile })
  }

  const files: string[] = []
  for (const write of pending) {
    writeYaml(root, write.file, write.value)
    files.push(write.file)
  }

  return {
    ok: true,
    api_id: id,
    extraction_method: extraction.method,
    source_url: url,
    retrieved_at: fetched.retrievedAt,
    files,
    message: `added \`${id}\` as an uncommitted candidate (${extraction.method} extraction from ${url} at ${fetched.retrievedAt})`,
  }
}

/** Shape of a `--candidate` file, validated rather than asserted. */
export const RefreshCandidateFile = z
  .object({
    source: z.string().min(1),
    revision: z.string().min(1),
    content_hash: z.string().min(1),
    records: z
      .array(
        z
          .object({ id: CanonicalId, fields: z.record(z.string(), z.unknown()).default({}) })
          .strict(),
      )
      .default([]),
  })
  .strict()

export interface RefreshCandidate {
  readonly source: string
  readonly revision: string
  readonly content_hash: string
  readonly records: { id: string; fields: Partial<Record<SourceOwnedField, unknown>> }[]
}

export interface RefreshReport {
  readonly ok: boolean
  readonly source: string
  readonly counts: { examined: number; updated: number; unchanged: number; conflicted: number }
  readonly conflicts: FieldConflict[]
  readonly rejections: { id: string; reason: string }[]
  readonly files: string[]
  readonly message: string
  readonly unchanged_revision?: boolean
}

/**
 * Field-level refresh from a pre-normalized candidate. Applies only
 * non-conflicting changes and reports the rest. This path writes no source
 * manifest and no ledger — `refresh <source>` does that.
 */
export function refreshFromCandidate(
  root: CatalogRoot,
  candidate: RefreshCandidate,
): RefreshReport {
  const snapshot = loadWorkingTree(root.path, root.git)
  const existing = snapshot.sourceManifests.get(candidate.source)

  // An unchanged upstream revision and content hash writes no diff.
  if (
    existing &&
    existing.value.revision === candidate.revision &&
    existing.value.content_hash === candidate.content_hash
  ) {
    return {
      ok: true,
      source: candidate.source,
      counts: { examined: 0, updated: 0, unchanged: 0, conflicted: 0 },
      conflicts: [],
      rejections: [],
      files: [],
      unchanged_revision: true,
      message: `\`${candidate.source}\` is unchanged at ${candidate.revision}; no catalog diff was written`,
    }
  }

  const conflicts: FieldConflict[] = []
  const rejections: { id: string; reason: string }[] = []
  const pending: { file: string; value: unknown }[] = []
  let updated = 0
  let unchanged = 0

  for (const entry of candidate.records) {
    const stored = snapshot.records.get(entry.id)
    if (!stored) {
      rejections.push({ id: entry.id, reason: 'no metadata record with that canonical id' })
      continue
    }
    const outcome = planFieldUpdates(stored.value, candidate.source, entry.fields)
    conflicts.push(...outcome.conflicts)
    if (outcome.updates.length === 0) {
      unchanged += 1
      continue
    }
    const next = applyFieldUpdates(stored.value, outcome.updates)
    const parsed = MetadataRecord.safeParse(next)
    if (!parsed.success) {
      rejections.push({
        id: entry.id,
        reason: parsed.error.issues.map((issue) => issue.message).join('; '),
      })
      continue
    }
    pending.push({ file: stored.file, value: parsed.data })
    updated += 1
  }

  // A candidate that fails validation applies no worktree change at all.
  if (rejections.length > 0) {
    return {
      ok: false,
      source: candidate.source,
      counts: {
        examined: candidate.records.length,
        updated: 0,
        unchanged,
        conflicted: conflicts.length,
      },
      conflicts,
      rejections,
      files: [],
      message: `the candidate catalog for \`${candidate.source}\` failed validation; no worktree change was applied`,
    }
  }

  const files: string[] = []
  for (const change of pending) {
    writeYaml(root, change.file, change.value)
    files.push(change.file)
  }

  return {
    ok: true,
    source: candidate.source,
    counts: {
      examined: candidate.records.length,
      updated,
      unchanged,
      conflicted: conflicts.length,
    },
    conflicts,
    rejections,
    files,
    message: `refreshed \`${candidate.source}\`: ${updated} updated, ${unchanged} unchanged, ${conflicts.length} conflict(s). This path writes no ledger; run \`refresh ${candidate.source}\` to record the pin.`,
  }
}

/** Sources whose adapter this build ships. */
export const SOURCE_IDS = ['public-apis', 'nango', 'apis-guru'] as const

export type SourceId = (typeof SOURCE_IDS)[number]

export interface SourceInput {
  readonly pin: SourcePin
  readonly payload: unknown
  /** Nango's separate scopes file. */
  readonly scopes?: unknown
  /** APIs.guru specifications already fetched, keyed by raw list id. */
  readonly specs?: Map<string, unknown>
}

export function runAdapter(sourceId: SourceId, input: SourceInput): AdapterRun {
  switch (sourceId) {
    case 'public-apis':
      return runPublicApis(input.payload, input.pin)
    case 'nango':
      return runNango(input.payload, input.pin, input.scopes)
    case 'apis-guru':
      return runApisGuru(input.payload, input.pin, input.specs)
  }
}

/** Run one source adapter over already-fetched input and apply its result. */
export function refreshSource(
  root: CatalogRoot,
  sourceId: SourceId,
  input: SourceInput,
): ApplyReport {
  return applyAdapterRun(root, runAdapter(sourceId, input))
}

/**
 * Already-fetched specifications, keyed by the upstream list id. The file stem
 * is the id with `/` written as `__`, since a list id may contain one.
 */
function readSpecs(directory: string): Map<string, unknown> {
  if (!existsSync(directory)) {
    throw new ApimanacError('usage', `no specification directory at ${directory}`)
  }
  const specs = new Map<string, unknown>()
  for (const relative of new Bun.Glob('*.{json,yaml,yml}').scanSync({ cwd: directory })) {
    const id = relative.replace(/\.(json|ya?ml)$/, '').replaceAll('__', '/')
    specs.set(id, readInput(join(directory, relative)))
  }
  if (specs.size === 0) {
    throw new ApimanacError('usage', `${directory} holds no .json or .yaml specification`)
  }
  return specs
}

function readInput(path: string): unknown {
  const text = readFileSync(path, 'utf8')
  try {
    return JSON.parse(text)
  } catch {
    return parse(text)
  }
}

export function runRefresh(root: CatalogRoot, argv: Argvish, io: Io, json: boolean): unknown {
  const source = argv.positional[0]
  const candidatePath = flag(argv, 'candidate')

  if (source) {
    if (!(SOURCE_IDS as readonly string[]).includes(source)) {
      throw new ApimanacError('usage', `unknown source \`${source}\``, {
        sources: [...SOURCE_IDS],
      })
    }
    const payloadPath = flag(argv, 'payload')
    const pinPath = flag(argv, 'pin')
    if (!payloadPath || !pinPath) {
      throw new ApimanacError(
        'usage',
        `refresh ${source} needs --payload <path> and --pin <path>${
          source === 'nango'
            ? ', optionally --scopes <path>'
            : source === 'apis-guru'
              ? ', optionally --specs <dir> to derive execution profiles'
              : ''
        }. Adapters take already-fetched input, so an offline build never opens a connection.`,
        { source, required: ['--payload', '--pin'] },
      )
    }
    const pinDocument = readInput(pinPath) as Record<string, unknown>
    const scopesPath = flag(argv, 'scopes')
    const specsDir = flag(argv, 'specs')
    const report = refreshSource(root, source as SourceId, {
      payload: readInput(payloadPath),
      scopes: scopesPath ? readInput(scopesPath) : undefined,
      specs: specsDir ? readSpecs(specsDir) : undefined,
      pin: {
        revision: String(pinDocument.revision ?? ''),
        contentHash: String(pinDocument.content_hash ?? ''),
        retrievedAt: String(pinDocument.retrieved_at ?? ''),
      },
    })
    if (json) return report
    io.out(report.message)
    for (const conflict of report.conflicts) {
      io.out(`  conflict ${conflict.record}.${conflict.field}: ${conflict.message}`)
    }
    for (const rejection of report.rejections) {
      io.out(`  rejected ${rejection.id}: ${rejection.reason_code} ${rejection.detail}`)
    }
    if (!report.ok) throw new ApimanacError('validation_failed', report.message)
    return undefined
  }

  if (!candidatePath) {
    throw new ApimanacError(
      'usage',
      `refresh needs a source (${SOURCE_IDS.join(', ')}) with --payload and --pin, or --candidate <path> holding a normalized field-level candidate`,
    )
  }
  if (!existsSync(candidatePath)) {
    throw new ApimanacError('usage', `no candidate file at ${candidatePath}`)
  }
  const parsed = RefreshCandidateFile.safeParse(parse(readFileSync(candidatePath, 'utf8')))
  if (!parsed.success) {
    throw new ApimanacError(
      'usage',
      `${candidatePath} is not a valid refresh candidate: ${parsed.error.issues
        .map((issue) => `${issue.path.join('.')}: ${issue.message}`)
        .join('; ')}`,
    )
  }
  const report = refreshFromCandidate(root, parsed.data)
  if (json) return report
  io.out(report.message)
  for (const conflict of report.conflicts)
    io.out(`  conflict ${conflict.record}.${conflict.field}: ${conflict.message}`)
  for (const rejection of report.rejections)
    io.out(`  rejected ${rejection.id}: ${rejection.reason}`)
  if (!report.ok) throw new ApimanacError('validation_failed', report.message)
  return undefined
}

export interface MigrateResult {
  readonly ok: boolean
  readonly from: number
  readonly to: number
  readonly files: string[]
  readonly message: string
}

/**
 * `migrate` is a deterministic, self-validating schema step. Running it twice
 * over the same input produces byte-identical output.
 */
export function migrateCatalog(root: CatalogRoot): MigrateResult {
  const snapshot = loadWorkingTree(root.path, root.git)
  const manifest = snapshot.manifest
  if (!manifest) {
    throw new ApimanacError('validation_failed', 'the catalog root manifest is missing')
  }
  const from = manifest.schema_version
  if (from === SUPPORTED_SCHEMA_VERSION) {
    return {
      ok: true,
      from,
      to: SUPPORTED_SCHEMA_VERSION,
      files: [],
      message: `the catalog is already at schema version ${SUPPORTED_SCHEMA_VERSION}`,
    }
  }
  if (from > SUPPORTED_SCHEMA_VERSION) {
    throw new ApimanacError(
      'unsupported_schema_version',
      `the catalog declares schema version ${from}; this build supports ${SUPPORTED_SCHEMA_VERSION} and cannot migrate downwards`,
    )
  }

  // v0 has exactly one schema version, so migrating is normalizing every
  // tracked document through the current schemas and restamping the manifest.
  const files: string[] = []
  const written: { file: string; value: unknown }[] = [
    {
      file: 'catalog/manifest.yaml',
      value: { ...manifest, schema_version: SUPPORTED_SCHEMA_VERSION },
    },
  ]
  for (const entry of snapshot.records.values()) {
    written.push({ file: entry.file, value: MetadataRecord.parse(entry.value) })
  }
  for (const entry of snapshot.profiles.values()) {
    written.push({ file: entry.file, value: ExecutionProfile.parse(entry.value) })
  }

  // Self-validating: a result that would not validate modifies nothing.
  for (const change of written) {
    const text = stringify(change.value)
    const parsed = parse(text) as unknown
    if (change.file.startsWith('catalog/meta/') && !MetadataRecord.safeParse(parsed).success) {
      throw new ApimanacError('validation_failed', `migration would invalidate ${change.file}`)
    }
    if (
      change.file.startsWith('catalog/execution/') &&
      !ExecutionProfile.safeParse(parsed).success
    ) {
      throw new ApimanacError('validation_failed', `migration would invalidate ${change.file}`)
    }
  }

  // Catalog-level invariants are checked against the migrated documents before
  // any file is written, so a failure leaves the worktree untouched.
  const projected = validateCatalog(migratedSnapshot(snapshot, written))
  if (!projected.ok) {
    throw new ApimanacError('validation_failed', 'the migrated catalog does not validate', {
      findings: projected.findings,
    })
  }

  for (const change of written) {
    writeYaml(root, change.file, change.value)
    files.push(change.file)
  }

  return {
    ok: true,
    from,
    to: SUPPORTED_SCHEMA_VERSION,
    files,
    message: `migrated ${files.length} file(s) from schema version ${from} to ${SUPPORTED_SCHEMA_VERSION} as an uncommitted worktree change`,
  }
}

/** The catalog as the migration would leave it, for pre-write validation. */
function migratedSnapshot(
  base: CatalogSnapshot,
  written: readonly { file: string; value: unknown }[],
): CatalogSnapshot {
  const records = new Map(base.records)
  const profiles = new Map(base.profiles)
  let manifest = base.manifest
  for (const change of written) {
    const entry = { file: change.file, state: 'untracked' as const, draft: true }
    if (change.file === MANIFEST_PATH) {
      manifest = RootManifest.parse(change.value)
    } else if (change.file.startsWith(`${META_DIR}/`)) {
      const value = MetadataRecord.parse(change.value)
      records.set(value.id, { ...entry, value })
    } else if (change.file.startsWith(`${EXECUTION_DIR}/`)) {
      const value = ExecutionProfile.parse(change.value)
      profiles.set(`${value.api_id}/${value.profile_id}`, { ...entry, value })
    }
  }
  return { ...base, manifest, records, profiles, issues: [] }
}

export function runMigrate(root: CatalogRoot, _argv: Argvish, io: Io, json: boolean): unknown {
  const result = migrateCatalog(root)
  if (json) return result
  io.out(result.message)
  return undefined
}
