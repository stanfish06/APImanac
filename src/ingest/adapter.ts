import type { z } from 'zod'
import { canonicalHash, project } from '../catalog/canonical'
import { ApimanacError } from '../errors'
import { ALIAS_PATTERN } from '../schema/metadata'
import { REASON_VOCABULARIES, REJECTION_DETAIL_MAX, type ReasonVocabulary } from '../schema/reasons'
import { countLedger, type LedgerEntry, OutcomeLedger, SourceManifest } from '../schema/report'
import { slugify } from '../schema/vocab'

export { slugify }

/**
 * The contract every source adapter implements. An adapter receives an
 * already-fetched payload and returns candidates plus a complete accounting of
 * the upstream entries it saw; it never opens a connection and never decides
 * that anything is verified.
 */

export interface SourcePin {
  revision: string
  contentHash: string
  retrievedAt: string
}

export interface MetadataCandidate {
  /** A `MetadataRecord` input; the caller parses it before writing. */
  record: unknown
  sourceEntryId: string
  contentHash: string
}

export interface ExecutionCandidate {
  /** An `ExecutionProfile` input; the caller parses it before writing. */
  profile: unknown
  sourceEntryId: string
  contentHash: string
}

export interface Rejection {
  sourceEntryId: string
  contentHash: string
  reasonCode: string
  detail: string
}

export interface AdapterRun {
  sourceId: string
  pin: SourcePin
  metadata: MetadataCandidate[]
  execution: ExecutionCandidate[]
  aliased: { sourceEntryId: string; contentHash: string; apiId: string }[]
  rejections: Rejection[]
}

export interface SourceAdapter {
  readonly sourceId: string
  readonly reasons: ReasonVocabulary
  run(input: unknown, pin: SourcePin): AdapterRun
}

export function entryContentHash(normalizedEntry: unknown): string {
  return canonicalHash(project(normalizedEntry))
}

/** A stable source-scoped id for an entry whose upstream id is missing or unusable. */
export function derivedEntryId(sourceId: string, normalizedEntry: unknown): string {
  const hex = entryContentHash(normalizedEntry).replace('v1:sha256:', '')
  return `${sourceId}:sha256-${hex.slice(0, 16)}`
}

export function truncateDetail(text: string): string {
  return text.length > REJECTION_DETAIL_MAX ? text.slice(0, REJECTION_DETAIL_MAX) : text
}

/** A canonical id slug: lowercase alphanumeric runs joined by single hyphens. */

/** The raw upstream name as an alias, or `undefined` when it cannot be one. */
export function aliasFor(raw: string): string | undefined {
  const value = raw
    .trim()
    .toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[^a-z0-9._:@/-]/g, '')
  return ALIAS_PATTERN.test(value) ? value : undefined
}

export function sourceVocabulary(sourceId: string): ReasonVocabulary {
  const vocabulary = REASON_VOCABULARIES[sourceId]
  if (!vocabulary) {
    throw new ApimanacError(
      'validation_failed',
      `no declared rejection reason vocabulary for source \`${sourceId}\``,
      { source: sourceId },
    )
  }
  return vocabulary
}

/** Ingestion produces candidates only; a verified profile can only come from `apimanac verify`. */
export function assertNoVerifiedProfiles(run: AdapterRun): void {
  for (const candidate of run.execution) {
    const state = (candidate.profile as { verification?: { state?: unknown } }).verification?.state
    if (state === 'verified') {
      throw new ApimanacError(
        'validation_failed',
        `source \`${run.sourceId}\` emitted a verified profile for entry \`${candidate.sourceEntryId}\`; ingestion produces candidates only`,
        { source: run.sourceId, entry: candidate.sourceEntryId },
      )
    }
  }
}

function importedApiId(sourceId: string, candidate: MetadataCandidate): string {
  const id = (candidate.record as { id?: unknown }).id
  if (typeof id !== 'string') {
    throw new ApimanacError(
      'validation_failed',
      `source \`${sourceId}\` emitted a metadata candidate for entry \`${candidate.sourceEntryId}\` with no canonical id`,
      { source: sourceId, entry: candidate.sourceEntryId },
    )
  }
  return id
}

/** Exactly one outcome per upstream entry, ordered by entry id so the file is stable. */
export function buildLedger(run: AdapterRun): OutcomeLedger {
  assertNoVerifiedProfiles(run)
  const entries: LedgerEntry[] = []
  for (const candidate of run.metadata) {
    entries.push({
      source_entry_id: candidate.sourceEntryId,
      content_hash: candidate.contentHash,
      outcome: 'imported',
      api_id: importedApiId(run.sourceId, candidate),
    })
  }
  for (const alias of run.aliased) {
    entries.push({
      source_entry_id: alias.sourceEntryId,
      content_hash: alias.contentHash,
      outcome: 'aliased',
      api_id: alias.apiId,
    })
  }
  for (const rejection of run.rejections) {
    entries.push({
      source_entry_id: rejection.sourceEntryId,
      content_hash: rejection.contentHash,
      outcome: 'rejected',
      reason_code: rejection.reasonCode,
      detail: truncateDetail(rejection.detail),
    })
  }
  const seen = new Set<string>()
  for (const entry of entries) {
    if (seen.has(entry.source_entry_id)) {
      throw new ApimanacError(
        'validation_failed',
        `source \`${run.sourceId}\` records two outcomes for entry \`${entry.source_entry_id}\``,
        { source: run.sourceId, entry: entry.source_entry_id },
      )
    }
    seen.add(entry.source_entry_id)
  }
  entries.sort((a, b) => compare(a.source_entry_id, b.source_entry_id))
  return {
    source_id: run.sourceId,
    reason_codes_version: sourceVocabulary(run.sourceId).version,
    entries,
  }
}

/** Hashes the ledger the way `validateCatalog` recomputes it: over the parsed document. */
export function ledgerHash(ledger: OutcomeLedger): string {
  return canonicalHash(JSON.parse(JSON.stringify(ledger)) as unknown)
}

export function buildManifest(
  run: AdapterRun,
  meta: { name: string; homepage?: string; license: string },
): SourceManifest {
  const ledger = OutcomeLedger.parse(buildLedger(run))
  return SourceManifest.parse({
    source_id: run.sourceId,
    name: meta.name,
    homepage: meta.homepage,
    license: meta.license,
    revision: run.pin.revision,
    content_hash: run.pin.contentHash,
    retrieved_at: run.pin.retrievedAt,
    reason_codes_version: ledger.reason_codes_version,
    counts: countLedger(ledger),
    ledger_hash: ledgerHash(ledger),
  })
}

/** Flattens a Zod failure into one line naming each offending path. */
export function describeIssues(error: z.ZodError): string {
  return error.issues
    .map((issue) => `${issue.path.join('.') || '<root>'}: ${issue.message}`)
    .join('; ')
}

export function compare(a: string, b: string): number {
  return a < b ? -1 : a > b ? 1 : 0
}
