import type { MetadataRecord, ProvenanceEntry } from '../schema/metadata'
import { SOURCE_OWNED_FIELDS, type SourceOwnedField } from '../schema/metadata'

/**
 * Per-field provenance and the field update rules. A source may update a field
 * it owns only while the current value still matches what that source last
 * supplied, and an empty value is never an instruction to clear a populated one.
 */

export type ConflictReason =
  | 'curated'
  | 'owned_by_other_source'
  | 'diverged_from_last_observed'
  | 'sparse_value'
  | 'upstream_disappeared'

export interface FieldConflict {
  readonly record: string
  readonly field: string
  readonly source: string
  readonly reason: ConflictReason
  readonly current: string
  readonly proposed: string
  readonly message: string
}

export interface FieldUpdate {
  readonly record: string
  readonly field: SourceOwnedField
  readonly source: string
  readonly value: unknown
  readonly lastObserved: string
}

export interface UpdateOutcome {
  readonly updates: FieldUpdate[]
  readonly conflicts: FieldConflict[]
}

/** Text form used for `last_observed` and for conflict reporting. */
export function observedText(value: unknown): string {
  if (value === undefined || value === null) return ''
  if (typeof value === 'string') return value
  if (Array.isArray(value)) return value.map((item) => observedText(item)).join('\n')
  return JSON.stringify(value)
}

function isSparse(value: unknown): boolean {
  if (value === undefined || value === null) return true
  if (typeof value === 'string') return value.trim() === ''
  if (Array.isArray(value)) return value.length === 0
  return false
}

function isPopulated(value: unknown): boolean {
  return !isSparse(value)
}

function fieldValue(record: MetadataRecord, field: SourceOwnedField): unknown {
  return (record as unknown as Record<string, unknown>)[field]
}

/**
 * Decide, field by field, what a source may write. Nothing here mutates the
 * record; callers apply `updates` and report `conflicts`.
 */
export function planFieldUpdates(
  record: MetadataRecord,
  source: string,
  proposed: Partial<Record<SourceOwnedField, unknown>>,
): UpdateOutcome {
  const updates: FieldUpdate[] = []
  const conflicts: FieldConflict[] = []

  for (const field of SOURCE_OWNED_FIELDS) {
    if (!(field in proposed)) continue
    const next = proposed[field]
    const current = fieldValue(record, field)
    const entry: ProvenanceEntry | undefined = record.provenance[field]

    const conflict = (reason: ConflictReason, message: string): void => {
      conflicts.push({
        record: record.id,
        field,
        source,
        reason,
        current: observedText(current),
        proposed: observedText(next),
        message,
      })
    }

    // An empty source value never blanks a richer stored one.
    if (isSparse(next)) {
      if (isPopulated(current)) {
        conflict(
          'sparse_value',
          `\`${source}\` now supplies an empty ${field}; the stored value is kept`,
        )
      }
      continue
    }

    if (entry?.curated) {
      if (observedText(current) !== observedText(next)) {
        conflict('curated', `${field} is curated; \`${source}\` cannot overwrite it`)
      }
      continue
    }

    if (entry && entry.source !== source) {
      if (observedText(current) !== observedText(next)) {
        conflict(
          'owned_by_other_source',
          `${field} is owned by \`${entry.source}\`; \`${source}\` proposes a different value`,
        )
      }
      continue
    }

    if (entry && observedText(current) !== observedText(entry.last_observed ?? '')) {
      conflict(
        'diverged_from_last_observed',
        `${field} no longer matches what \`${source}\` last supplied, so it is left unchanged`,
      )
      continue
    }

    if (!entry && isPopulated(current) && observedText(current) !== observedText(next)) {
      conflict(
        'curated',
        `${field} has a value with no recorded provenance; \`${source}\` cannot overwrite it`,
      )
      continue
    }

    if (observedText(current) === observedText(next)) continue
    updates.push({
      record: record.id,
      field,
      source,
      value: next,
      lastObserved: observedText(next),
    })
  }

  return { updates, conflicts }
}

/** An entry that vanished upstream leaves the record and lifecycle unchanged. */
export function upstreamDisappearance(record: MetadataRecord, source: string): FieldConflict {
  return {
    record: record.id,
    field: 'lifecycle',
    source,
    reason: 'upstream_disappeared',
    current: record.lifecycle,
    proposed: record.lifecycle,
    message: `\`${source}\` no longer lists this API; the record and its lifecycle are unchanged and only a reviewed metadata change can set \`gone\``,
  }
}

/** Apply planned updates to a copy of the record, refreshing provenance. */
export function applyFieldUpdates(
  record: MetadataRecord,
  updates: readonly FieldUpdate[],
): MetadataRecord {
  if (updates.length === 0) return record
  const next = structuredClone(record) as MetadataRecord
  const writable = next as unknown as Record<string, unknown>
  for (const update of updates) {
    writable[update.field] = update.value
    next.provenance = {
      ...next.provenance,
      [update.field]: { source: update.source, last_observed: update.lastObserved, curated: false },
    }
  }
  return next
}
