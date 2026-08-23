import type { MetadataRecord } from '../schema/metadata'
import type { CatalogIssue, LoadedFile } from './load'

/**
 * Canonical ids, aliases, and reviewed merge redirects. Source ids are aliases,
 * never identity, and a merge is a redirect a reviewer wrote — never something
 * a matching name or shared domain produced.
 */

export interface Resolution {
  /** The canonical record the lookup lands on. */
  readonly id: string
  readonly requested: string
  /** Set when the requested string was an alias rather than a canonical id. */
  readonly viaAlias?: string
  /** Merge redirect chain walked, from the requested id to the target. */
  readonly viaMerge?: readonly string[]
}

export interface IdentityIndex {
  resolve(requested: string): Resolution | undefined
  /** Canonical ids, sorted. */
  ids(): string[]
  /** Every alias pointing at this canonical id, sorted. */
  aliasesOf(id: string): string[]
  readonly issues: readonly CatalogIssue[]
}

export function buildIdentityIndex(
  records: ReadonlyMap<string, LoadedFile<MetadataRecord>>,
): IdentityIndex {
  const issues: CatalogIssue[] = []
  const aliasToId = new Map<string, string>()
  const aliasOwners = new Map<string, string[]>()

  const sorted = [...records.values()].sort((a, b) => (a.file < b.file ? -1 : 1))

  for (const entry of sorted) {
    for (const alias of entry.value.aliases) {
      const owners = aliasOwners.get(alias) ?? []
      owners.push(entry.file)
      aliasOwners.set(alias, owners)
      if (!aliasToId.has(alias)) aliasToId.set(alias, entry.value.id)
    }
  }

  for (const [alias, owners] of [...aliasOwners].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const clashesWithCanonical = records.has(alias)
    if (owners.length > 1 || clashesWithCanonical) {
      const participants = [...owners]
      if (clashesWithCanonical) {
        const owner = records.get(alias)
        if (owner) participants.push(owner.file)
      }
      issues.push({
        kind: 'alias_collision',
        file: participants[0] ?? '<unknown>',
        field: 'aliases',
        message: `alias \`${alias}\` is claimed by ${[...new Set(participants)].sort().join(', ')}`,
      })
    }
  }

  // A merge redirect must terminate at a record that is not itself merged.
  const mergeTarget = new Map<string, { id: string; chain: string[] } | undefined>()
  for (const entry of sorted) {
    const record = entry.value
    if (record.lifecycle !== 'merged') continue
    const chain: string[] = [record.id]
    const seen = new Set<string>([record.id])
    let current: MetadataRecord | undefined = record
    let resolved: string | undefined
    while (current) {
      const next: string | undefined = current.merged_into
      if (!next) {
        resolved = current.id
        break
      }
      if (seen.has(next)) {
        issues.push({
          kind: 'merge_cycle',
          file: entry.file,
          field: 'merged_into',
          message: `merge redirect cycles through ${[...chain, next].join(' -> ')}`,
        })
        break
      }
      const target = records.get(next)
      if (!target) {
        issues.push({
          kind: 'merge_dangling',
          file: entry.file,
          field: 'merged_into',
          message: `merge redirect ${[...chain, next].join(' -> ')} ends at \`${next}\`, which has no record`,
        })
        break
      }
      chain.push(next)
      seen.add(next)
      if (target.value.lifecycle !== 'merged') {
        resolved = target.value.id
        break
      }
      current = target.value
    }
    mergeTarget.set(record.id, resolved ? { id: resolved, chain } : undefined)
  }

  const resolve = (requested: string): Resolution | undefined => {
    let viaAlias: string | undefined
    let id = requested
    if (!records.has(id)) {
      const target = aliasToId.get(requested)
      if (!target) return undefined
      viaAlias = requested
      id = target
    }
    const merge = mergeTarget.get(id)
    if (merge) return { id: merge.id, requested, viaAlias, viaMerge: merge.chain }
    // A record whose merge chain failed validation resolves to itself.
    return { id, requested, viaAlias }
  }

  const aliasesByTarget = new Map<string, string[]>()
  for (const [alias, id] of aliasToId) {
    const list = aliasesByTarget.get(id) ?? []
    list.push(alias)
    aliasesByTarget.set(id, list)
  }
  for (const [id, merge] of mergeTarget) {
    if (!merge) continue
    const list = aliasesByTarget.get(merge.id) ?? []
    list.push(id)
    aliasesByTarget.set(merge.id, list)
  }

  return {
    resolve,
    ids: () => [...records.keys()].sort(),
    aliasesOf: (id) => [...new Set(aliasesByTarget.get(id) ?? [])].sort(),
    issues,
  }
}
