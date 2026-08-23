import { z } from 'zod'
import { ApimanacError } from '../errors'
import { PUBLIC_APIS_REASONS } from '../schema/reasons'
import {
  type AdapterRun,
  aliasFor,
  assertNoVerifiedProfiles,
  derivedEntryId,
  describeIssues,
  entryContentHash,
  type MetadataCandidate,
  type SourceAdapter,
  type SourcePin,
  slugify,
  truncateDetail,
} from './adapter'

/**
 * public-apis is a discovery directory: names, categories, and documentation
 * links. Nothing here describes how to call an API, so the adapter emits
 * metadata only — no origin is derived from a documentation link and the coarse
 * `Auth` label stays a descriptive tag.
 */

const SOURCE_ID = 'public-apis'

const PublicApisEntry = z
  .object({
    API: z.string().optional(),
    Description: z.string().optional(),
    Auth: z.string().optional(),
    HTTPS: z.boolean().optional(),
    Cors: z.string().optional(),
    Link: z.string().optional(),
    Category: z.string().optional(),
  })
  .strict()

const PublicApisPayload = z
  .object({
    count: z.number().int().nonnegative(),
    entries: z.array(z.unknown()),
  })
  .strict()

/** The coarse upstream label, kept as a tag rather than an executable auth shape. */
function authTag(label: string | undefined): string {
  const value = slugify(label ?? '')
  return value ? `auth:${value}` : 'auth:none'
}

function documentationUrl(link: string): string | undefined {
  let parsed: URL
  try {
    parsed = new URL(link)
  } catch {
    return undefined
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return undefined
  return parsed.toString()
}

export function runPublicApis(input: unknown, pin: SourcePin): AdapterRun {
  const payload = PublicApisPayload.safeParse(input)
  if (!payload.success) {
    throw new ApimanacError(
      'validation_failed',
      `source \`${SOURCE_ID}\`: upstream payload is not \`{ count, entries[] }\` — ${describeIssues(payload.error)}`,
      { source: SOURCE_ID, shape: describeIssues(payload.error) },
    )
  }

  const run: AdapterRun = {
    sourceId: SOURCE_ID,
    pin,
    metadata: [],
    execution: [],
    aliased: [],
    rejections: [],
  }
  const bySlug = new Map<string, MetadataCandidate>()

  for (const raw of payload.data.entries) {
    const contentHash = entryContentHash(raw)
    const parsed = PublicApisEntry.safeParse(raw)
    if (!parsed.success) {
      run.rejections.push({
        sourceEntryId: derivedEntryId(SOURCE_ID, raw),
        contentHash,
        reasonCode: 'schema_mismatch',
        detail: truncateDetail(describeIssues(parsed.error)),
      })
      continue
    }

    const entry = parsed.data
    const name = entry.API?.trim() ?? ''
    const sourceEntryId = name === '' ? derivedEntryId(SOURCE_ID, raw) : (entry.API ?? '')
    const reject = (reasonCode: string, detail: string) => {
      run.rejections.push({
        sourceEntryId,
        contentHash,
        reasonCode,
        detail: truncateDetail(detail),
      })
    }

    if (name === '') {
      reject('missing_name', 'entry declares no `API` name')
      continue
    }
    const link = entry.Link?.trim() ?? ''
    if (link === '') {
      reject('missing_link', 'entry declares no `Link`')
      continue
    }
    const documentation = documentationUrl(link)
    if (!documentation) {
      reject('invalid_link', `\`Link\` \`${link}\` is not an http or https URL`)
      continue
    }
    const category = entry.Category?.trim() ?? ''
    if (category === '') {
      reject('unusable_category', 'entry declares no `Category`')
      continue
    }
    const id = slugify(name)
    if (id === '') {
      reject('missing_name', `\`API\` \`${name}\` slugifies to an empty canonical id`)
      continue
    }

    const alias = aliasFor(name)
    const existing = bySlug.get(id)
    if (existing) {
      const record = existing.record as { aliases: string[] }
      if (alias && alias !== id && !record.aliases.includes(alias)) record.aliases.push(alias)
      run.aliased.push({ sourceEntryId, contentHash, apiId: id })
      continue
    }

    const label = entry.Auth ?? ''
    const candidate: MetadataCandidate = {
      sourceEntryId,
      contentHash,
      record: {
        id,
        name,
        description: entry.Description ?? '',
        documentation,
        categories: [category],
        tags: [authTag(label)],
        aliases: alias && alias !== id ? [alias] : [],
        sources: [SOURCE_ID],
        provenance: {
          name: { source: SOURCE_ID, last_observed: name, curated: false },
          description: {
            source: SOURCE_ID,
            last_observed: entry.Description ?? '',
            curated: false,
          },
          documentation: { source: SOURCE_ID, last_observed: link, curated: false },
          categories: { source: SOURCE_ID, last_observed: category, curated: false },
          tags: { source: SOURCE_ID, last_observed: label, curated: false },
        },
      },
    }
    bySlug.set(id, candidate)
    run.metadata.push(candidate)
  }

  assertNoVerifiedProfiles(run)
  return run
}

export const publicApisAdapter: SourceAdapter = {
  sourceId: SOURCE_ID,
  reasons: PUBLIC_APIS_REASONS,
  run: runPublicApis,
}
