interface Ctx {
  params: { topic: string; years?: number[]; per_year: number }
  api: {
    call(
      profile: string,
      request: { method?: string; path: string; query?: Record<string, string> },
    ): Promise<{ outcome: string; status?: number; body?: string }>
  }
}

interface Work {
  id: string
  title: string | null
  publication_year: number
  cited_by_count: number
}

export default async function run(ctx: Ctx) {
  const years = ctx.params.years?.length ? ctx.params.years : [new Date().getUTCFullYear()]
  const collected: Work[] = []

  // One call per year, sorted by citations. The profile's cache policy applies.
  const responses = await Promise.all(
    years.map((year) =>
      ctx.api.call('openalex/public', {
        method: 'GET',
        path: '/works',
        query: {
          filter: `topics.id:${ctx.params.topic},publication_year:${year}`,
          sort: 'cited_by_count:desc',
          per_page: String(ctx.params.per_year),
        },
      }),
    ),
  )

  for (const response of responses) {
    if (response.outcome !== 'success' || !response.body) continue
    const parsed = JSON.parse(response.body) as { results?: Work[] }
    for (const work of parsed.results ?? []) collected.push(work)
  }

  collected.sort((a, b) => b.cited_by_count - a.cited_by_count)
  return {
    topic: ctx.params.topic,
    sampled_years: years,
    top: collected.slice(0, 10).map((work) => ({
      id: work.id,
      title: work.title,
      year: work.publication_year,
      cited_by_count: work.cited_by_count,
    })),
  }
}
