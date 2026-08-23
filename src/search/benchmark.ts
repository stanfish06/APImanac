import { z } from 'zod'
import type { CatalogQuery } from './query'

/**
 * The committed search benchmark. `queries.yaml` carries its relevance labels
 * and is authored before the weights are tuned, so the threshold is a gate
 * rather than a description of whatever the ranking happens to do.
 */

export const TOP_N = 5
export const REQUIRED_HITS = 16

export const BenchmarkFile = z
  .object({
    version: z.number().int().positive(),
    queries: z
      .array(
        z
          .object({
            id: z.string().min(1),
            text: z.string().min(1),
            relevant: z.array(z.string().min(1)).min(1),
          })
          .strict(),
      )
      .length(20),
    exact: z
      .array(z.object({ query: z.string().min(1), expect: z.string().min(1) }).strict())
      .min(1),
  })
  .strict()

export type BenchmarkFile = z.infer<typeof BenchmarkFile>

export interface QueryOutcome {
  readonly id: string
  readonly text: string
  readonly hit: boolean
  /** 1-based rank of the first relevant result, or undefined when none appeared. */
  readonly rank?: number
  readonly returned: string[]
}

export interface ExactOutcome {
  readonly query: string
  readonly expect: string
  readonly actual?: string
  readonly ok: boolean
}

export interface BenchmarkReport {
  readonly queries: QueryOutcome[]
  readonly exact: ExactOutcome[]
  readonly hits: number
  readonly total: number
  readonly exactOk: boolean
  readonly ok: boolean
}

export function runBenchmark(catalog: CatalogQuery, fixture: BenchmarkFile): BenchmarkReport {
  const queries: QueryOutcome[] = fixture.queries.map((entry) => {
    const returned = catalog.search(entry.text, { limit: TOP_N }).results.map((result) => result.id)
    const index = returned.findIndex((id) => entry.relevant.includes(id))
    return {
      id: entry.id,
      text: entry.text,
      hit: index >= 0,
      rank: index >= 0 ? index + 1 : undefined,
      returned,
    }
  })

  const exact: ExactOutcome[] = fixture.exact.map((entry) => {
    const first = catalog.search(entry.query, { limit: TOP_N }).results[0]
    return {
      query: entry.query,
      expect: entry.expect,
      actual: first?.id,
      ok: first?.id === entry.expect,
    }
  })

  const hits = queries.filter((outcome) => outcome.hit).length
  const exactOk = exact.every((outcome) => outcome.ok)
  return {
    queries,
    exact,
    hits,
    total: queries.length,
    exactOk,
    ok: hits >= REQUIRED_HITS && exactOk,
  }
}

export function formatBenchmark(report: BenchmarkReport): string {
  const lines = report.queries.map(
    (outcome) =>
      `${outcome.hit ? 'hit ' : 'MISS'} ${outcome.id} rank=${outcome.rank ?? '-'} "${outcome.text}" -> ${outcome.returned.join(', ')}`,
  )
  for (const outcome of report.exact) {
    lines.push(
      `${outcome.ok ? 'hit ' : 'MISS'} exact "${outcome.query}" expected ${outcome.expect}, got ${outcome.actual ?? '<none>'}`,
    )
  }
  lines.push(
    `${report.hits}/${report.total} relevant in the top ${TOP_N}; ${REQUIRED_HITS} required`,
  )
  return lines.join('\n')
}
