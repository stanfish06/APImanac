import { z } from 'zod'
import { TaggedHash } from './execution'
import { REASON_VOCABULARIES, REJECTION_DETAIL_MAX } from './reasons'
import { CanonicalId } from './vocab'

/**
 * Adapter accounting. Every upstream entry appears exactly once in a source's
 * `outcomes.yaml`, and the source manifest records the counts and ledger hash.
 */

export const OutcomeCounts = z
  .object({
    total: z.number().int().nonnegative(),
    imported: z.number().int().nonnegative(),
    aliased: z.number().int().nonnegative(),
    rejected: z.number().int().nonnegative(),
  })
  .strict()

export const SourceManifest = z
  .object({
    source_id: CanonicalId,
    name: z.string().min(1),
    homepage: z.string().url().optional(),
    license: z.string().min(1),
    /** Upstream revision this run pinned: a commit id, tag, or dated version. */
    revision: z.string().min(1),
    /** Digest of the upstream payload the run consumed. */
    content_hash: TaggedHash,
    retrieved_at: z.string().min(1),
    reason_codes_version: z.number().int().positive(),
    counts: OutcomeCounts,
    ledger_hash: TaggedHash,
  })
  .strict()

const ImportedOutcome = z
  .object({
    source_entry_id: z.string().min(1),
    content_hash: TaggedHash,
    outcome: z.literal('imported'),
    api_id: CanonicalId,
  })
  .strict()

const AliasedOutcome = z
  .object({
    source_entry_id: z.string().min(1),
    content_hash: TaggedHash,
    outcome: z.literal('aliased'),
    api_id: CanonicalId,
  })
  .strict()

const RejectedOutcome = z
  .object({
    source_entry_id: z.string().min(1),
    content_hash: TaggedHash,
    outcome: z.literal('rejected'),
    reason_code: z.string().min(1),
    detail: z.string().max(REJECTION_DETAIL_MAX).default(''),
  })
  .strict()

export const LedgerEntry = z.discriminatedUnion('outcome', [
  ImportedOutcome,
  AliasedOutcome,
  RejectedOutcome,
])

export const OutcomeLedger = z
  .object({
    source_id: CanonicalId,
    reason_codes_version: z.number().int().positive(),
    entries: z.array(LedgerEntry).default([]),
  })
  .strict()
  .superRefine((value, ctx) => {
    const seen = new Set<string>()
    for (const entry of value.entries) {
      if (seen.has(entry.source_entry_id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['entries'],
          message: `source \`${value.source_id}\` records two outcomes for entry \`${entry.source_entry_id}\``,
        })
      }
      seen.add(entry.source_entry_id)
    }
    const vocabulary = REASON_VOCABULARIES[value.source_id]
    if (!vocabulary) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['source_id'],
        message: `no declared rejection reason vocabulary for source \`${value.source_id}\``,
      })
      return
    }
    if (vocabulary.version !== value.reason_codes_version) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['reason_codes_version'],
        message: `ledger declares reason vocabulary version ${value.reason_codes_version}, this build declares ${vocabulary.version}`,
      })
    }
    for (const entry of value.entries) {
      if (entry.outcome !== 'rejected') continue
      if (!vocabulary.codes.includes(entry.reason_code)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['entries'],
          message: `entry \`${entry.source_entry_id}\` cites reason code \`${entry.reason_code}\`, which source \`${value.source_id}\` does not declare`,
        })
      }
    }
  })

export function countLedger(ledger: OutcomeLedger): OutcomeCounts {
  const counts = { total: ledger.entries.length, imported: 0, aliased: 0, rejected: 0 }
  for (const entry of ledger.entries) counts[entry.outcome] += 1
  return counts
}

export type OutcomeCounts = z.infer<typeof OutcomeCounts>
export type SourceManifest = z.infer<typeof SourceManifest>
export type LedgerEntry = z.infer<typeof LedgerEntry>
export type OutcomeLedger = z.infer<typeof OutcomeLedger>
