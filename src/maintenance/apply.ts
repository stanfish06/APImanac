import { mkdirSync, writeFileSync } from 'node:fs'
import { dirname, join } from 'node:path'
import { stringify } from 'yaml'
import {
  EXECUTION_DIR,
  META_DIR,
  type CatalogSnapshot,
  loadWorkingTree,
  metadataPath,
  profilePath,
} from '../catalog/load'
import { planFieldUpdates, applyFieldUpdates, type FieldConflict } from '../catalog/provenance'
import type { CatalogRoot } from '../catalog/root'
import { validateCatalog } from '../catalog/validate'
import { buildIdentityIndex } from '../catalog/identity'
import { buildLedger, buildManifest, type AdapterRun } from '../ingest/adapter'
import { ExecutionProfile } from '../schema/execution'
import { MetadataRecord, SOURCE_OWNED_FIELDS, type SourceOwnedField } from '../schema/metadata'
import { OutcomeLedger, SourceManifest } from '../schema/report'

/**
 * Applies an adapter run to the worktree: non-conflicting metadata fields,
 * candidate execution profiles, and the tracked outcome ledger. Everything is
 * left as an uncommitted diff, and a candidate catalog that fails validation
 * applies nothing.
 */

export interface ApplyReport {
  readonly ok: boolean
  readonly source: string
  readonly counts: {
    readonly examined: number
    readonly imported: number
    readonly aliased: number
    readonly rejected: number
    readonly created: number
    readonly updated: number
    readonly unchanged: number
  }
  readonly conflicts: FieldConflict[]
  readonly rejections: { id: string; reason_code: string; detail: string }[]
  readonly files: string[]
  readonly message: string
}

interface PendingWrite {
  readonly file: string
  readonly value: unknown
}

function sourceOwnedFields(record: unknown): Partial<Record<SourceOwnedField, unknown>> {
  const source = record as Record<string, unknown>
  const fields: Partial<Record<SourceOwnedField, unknown>> = {}
  for (const field of SOURCE_OWNED_FIELDS) {
    if (source[field] !== undefined) fields[field] = source[field]
  }
  return fields
}

export function applyAdapterRun(root: CatalogRoot, run: AdapterRun): ApplyReport {
  const snapshot = loadWorkingTree(root.path, root.git)
  const identity = buildIdentityIndex(snapshot.records)
  /** Entries the catalog resolves to an existing identity, by source entry id. */
  const aliasedTo = new Map<string, string>()
  const conflicts: FieldConflict[] = []
  const pending: PendingWrite[] = []
  const failures: string[] = []
  let created = 0
  let updated = 0
  let unchanged = 0

  for (const candidate of run.metadata) {
    const parsed = MetadataRecord.safeParse(candidate.record)
    if (!parsed.success) {
      failures.push(
        `${candidate.sourceEntryId}: ${parsed.error.issues.map((issue) => issue.message).join('; ')}`,
      )
      continue
    }
    const proposed = parsed.data
    const stored = snapshot.records.get(proposed.id)
    if (!stored) {
      // A new id or alias already claimed by another record stays a distinct,
      // source-qualified candidate until a reviewer merges it.
      const claimed = [proposed.id, ...proposed.aliases]
        .map((name) => identity.resolve(name))
        .find((resolution) => resolution !== undefined)
      if (claimed) {
        // The adapter cannot see the catalog, so the entry it recorded as
        // `imported` is resolved here to the identity that already owns it.
        aliasedTo.set(candidate.sourceEntryId, claimed.id)
        conflicts.push({
          record: proposed.id,
          field: 'id',
          source: run.sourceId,
          reason: 'owned_by_other_source',
          current: claimed.id,
          proposed: proposed.id,
          message: `\`${run.sourceId}\` proposes \`${proposed.id}\`, whose identity \`${claimed.requested}\` already resolves to \`${claimed.id}\`; the entry is recorded as an alias of it`,
        })
        continue
      }
      pending.push({ file: metadataPath(proposed.id), value: proposed })
      created += 1
      continue
    }
    const outcome = planFieldUpdates(stored.value, run.sourceId, sourceOwnedFields(proposed))
    conflicts.push(...outcome.conflicts)
    if (outcome.updates.length === 0) {
      unchanged += 1
      continue
    }
    const next = applyFieldUpdates(stored.value, outcome.updates)
    const revalidated = MetadataRecord.safeParse(next)
    if (!revalidated.success) {
      failures.push(
        `${proposed.id}: ${revalidated.error.issues.map((issue) => issue.message).join('; ')}`,
      )
      continue
    }
    pending.push({ file: stored.file, value: revalidated.data })
    updated += 1
  }

  for (const candidate of run.execution) {
    // The metadata for this entry was resolved to an identity the catalog
    // already owns, so its profile would reference an api that was never written.
    if (aliasedTo.has(candidate.sourceEntryId)) continue
    const parsed = ExecutionProfile.safeParse(candidate.profile)
    if (!parsed.success) {
      failures.push(
        `${candidate.sourceEntryId}: ${parsed.error.issues.map((issue) => issue.message).join('; ')}`,
      )
      continue
    }
    const profile = parsed.data
    if (profile.verification.state !== 'candidate') {
      failures.push(`${candidate.sourceEntryId}: an adapter may not produce a verified profile`)
      continue
    }
    const file = profilePath(profile.api_id, profile.profile_id)
    // A committed profile is never overwritten by an import; a reviewer owns it.
    if (
      snapshot.profiles.get(`${profile.api_id}/${profile.profile_id}`)?.state === 'tracked_clean'
    ) {
      unchanged += 1
      continue
    }
    pending.push({ file, value: profile })
  }

  const resolved = resolveAgainstCatalog(run, aliasedTo)
  const ledger = buildLedger(resolved)
  const manifest = buildManifest(resolved, {
    name: run.sourceId,
    license: sourceLicense(run.sourceId),
  })
  pending.push({ file: `catalog/sources/${run.sourceId}/outcomes.yaml`, value: ledger })
  pending.push({ file: `catalog/sources/${run.sourceId}/manifest.yaml`, value: manifest })

  const counts = {
    examined: resolved.metadata.length + resolved.aliased.length + resolved.rejections.length,
    imported: resolved.metadata.length,
    aliased: resolved.aliased.length,
    rejected: resolved.rejections.length,
    created,
    updated,
    unchanged,
  }
  const rejections = run.rejections.map((rejection) => ({
    id: rejection.sourceEntryId,
    reason_code: rejection.reasonCode,
    detail: rejection.detail,
  }))

  if (failures.length > 0) {
    return {
      ok: false,
      source: run.sourceId,
      counts: { ...counts, created: 0, updated: 0 },
      conflicts,
      rejections,
      files: [],
      message: `the candidate catalog for \`${run.sourceId}\` failed validation, so no worktree change was applied: ${failures.join(' | ')}`,
    }
  }

  // Validate the whole candidate catalog before any worktree file is touched,
  // so a failure applies nothing rather than leaving a dirty invalid tree.
  const projected = validateCatalog(projectPending(snapshot, pending))
  if (!projected.ok) {
    return {
      ok: false,
      source: run.sourceId,
      counts: { ...counts, created: 0, updated: 0 },
      conflicts,
      rejections,
      files: [],
      message: `the candidate catalog for \`${run.sourceId}\` does not validate, so no worktree change was applied: ${projected.findings
        .map((finding) => `${finding.kind} ${finding.file}`)
        .join(', ')}`,
    }
  }

  const files: string[] = []
  for (const write of pending) {
    const absolute = join(root.path, write.file)
    mkdirSync(dirname(absolute), { recursive: true })
    writeFileSync(absolute, stringify(write.value))
    files.push(write.file)
  }

  return {
    ok: true,
    source: run.sourceId,
    counts,
    conflicts,
    rejections,
    files,
    message: `applied \`${run.sourceId}\` at ${run.pin.revision}: ${counts.imported} imported, ${counts.aliased} aliased, ${counts.rejected} rejected; ${created} record(s) created, ${updated} updated, ${conflicts.length} conflict(s)`,
  }
}

/**
 * The catalog as it would be after the pending writes land, so catalog-level
 * invariants are checked against the result rather than the current tree.
 */
function projectPending(base: CatalogSnapshot, pending: readonly PendingWrite[]): CatalogSnapshot {
  const records = new Map(base.records)
  const profiles = new Map(base.profiles)
  const sourceManifests = new Map(base.sourceManifests)
  const ledgers = new Map(base.ledgers)

  for (const write of pending) {
    const entry = { file: write.file, state: 'untracked' as const, draft: true }
    if (write.file.startsWith(`${META_DIR}/`)) {
      const value = MetadataRecord.parse(write.value)
      records.set(value.id, { ...entry, value })
    } else if (write.file.startsWith(`${EXECUTION_DIR}/`)) {
      const value = ExecutionProfile.parse(write.value)
      profiles.set(`${value.api_id}/${value.profile_id}`, { ...entry, value })
    } else if (write.file.endsWith('/manifest.yaml')) {
      const value = SourceManifest.parse(write.value)
      sourceManifests.set(value.source_id, { ...entry, value })
    } else if (write.file.endsWith('/outcomes.yaml')) {
      const value = OutcomeLedger.parse(write.value)
      ledgers.set(value.source_id, { ...entry, value })
    }
  }
  return { ...base, records, profiles, sourceManifests, ledgers, issues: [] }
}

/** Move entries the catalog already owns from `imported` to `aliased`. */
function resolveAgainstCatalog(run: AdapterRun, aliasedTo: Map<string, string>): AdapterRun {
  if (aliasedTo.size === 0) return run
  const metadata = run.metadata.filter((entry) => !aliasedTo.has(entry.sourceEntryId))
  const aliased = [
    ...run.aliased,
    ...run.metadata
      .filter((entry) => aliasedTo.has(entry.sourceEntryId))
      .map((entry) => ({
        sourceEntryId: entry.sourceEntryId,
        contentHash: entry.contentHash,
        apiId: aliasedTo.get(entry.sourceEntryId) as string,
      })),
  ]
  return { ...run, metadata, aliased }
}

/** Licenses of the three v0 sources, recorded in every source manifest. */
export function sourceLicense(sourceId: string): string {
  switch (sourceId) {
    case 'public-apis':
      return 'MIT'
    case 'nango':
      return 'ELv2'
    case 'apis-guru':
      return 'CC0-1.0'
    default:
      return 'unknown'
  }
}
