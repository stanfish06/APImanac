import { z } from 'zod'
import { CanonicalId, CurationState, Lifecycle } from './vocab'

/** An alias may be a canonical slug or a source-qualified id such as `apis-guru:openalex.org`. */
export const ALIAS_PATTERN = /^[a-z0-9][a-z0-9._:@/-]*$/
export const Alias = z
  .string()
  .regex(ALIAS_PATTERN, 'alias contains characters outside the alias set')

export const ProvenanceEntry = z
  .object({
    /** Source id declared in the root manifest, or `manual` for a reviewer edit. */
    source: z.string().min(1),
    /** The value that source last supplied, as text; absent when it supplied none. */
    last_observed: z.string().optional(),
    curated: z.boolean().default(false),
  })
  .strict()

export const SpecReference = z
  .object({
    id: z.string().min(1),
    url: z.string().url(),
    /** `v1:sha256:<hex>` of the retrieved document, when one was retrieved. */
    hash: z.string().optional(),
    format: z.enum(['openapi-3', 'swagger-2', 'other']).optional(),
    /** Bounded human summary; the full document is never inlined into the catalog. */
    summary: z.string().max(2000).optional(),
    byte_size: z.number().int().nonnegative().optional(),
  })
  .strict()

/**
 * A link a reviewer attaches for the agent to read before or while using the
 * API: a prompt template repository, a worked example, a guide. The catalog
 * never fetches it; `show`/`get_api` only surface the link.
 */
export const ResourceLink = z
  .object({
    url: z.string().url(),
    /** One line on what the link holds, so the agent can decide whether to fetch it. */
    description: z.string().min(1).max(300).optional(),
  })
  .strict()

export const MetadataRecord = z
  .object({
    id: CanonicalId,
    name: z.string().min(1),
    /** The root manifest owns the schema version; a record repeating it is a contract error. */
    schema_version: z.undefined({
      invalid_type_error: 'the root manifest owns the schema version; a record must not repeat it',
    }),
    description: z.string().default(''),
    homepage: z.string().url().optional(),
    documentation: z.string().url().optional(),
    categories: z.array(z.string().min(1)).default([]),
    tags: z.array(z.string().min(1)).default([]),
    aliases: z.array(Alias).default([]),
    lifecycle: Lifecycle.default('active'),
    curation: CurationState.default('imported'),
    /** Required when lifecycle is `merged`: the canonical id lookups redirect to. */
    merged_into: CanonicalId.optional(),
    /** Unreviewed merge proposals. These never change resolution. */
    same_as: z.array(CanonicalId).default([]),
    sources: z.array(z.string().min(1)).default([]),
    provenance: z.record(z.string(), ProvenanceEntry).default({}),
    specs: z.array(SpecReference).default([]),
    capabilities: z.array(z.string().min(1).max(300)).default([]),
    /** Reviewer-owned; no source adapter writes it. */
    resources: z.array(ResourceLink).default([]),
    profiles: z.array(z.string().min(1)).default([]),
  })
  .strict()
  .superRefine((value, ctx) => {
    if (value.lifecycle === 'merged' && !value.merged_into) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['merged_into'],
        message: 'a `merged` record must name the canonical id it redirects to',
      })
    }
    if (value.lifecycle !== 'merged' && value.merged_into) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['merged_into'],
        message: '`merged_into` is only meaningful on a `merged` record',
      })
    }
    if (value.merged_into === value.id) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['merged_into'],
        message: 'a record cannot redirect to itself',
      })
    }
    if (value.aliases.includes(value.id)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['aliases'],
        message: 'a record cannot alias its own canonical id',
      })
    }
    const seenResources = new Set<string>()
    for (const resource of value.resources) {
      if (seenResources.has(resource.url)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['resources'],
          message: `duplicate resource \`${resource.url}\``,
        })
      }
      seenResources.add(resource.url)
    }
    const seen = new Set<string>()
    for (const alias of value.aliases) {
      if (seen.has(alias)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['aliases'],
          message: `duplicate alias \`${alias}\``,
        })
      }
      seen.add(alias)
    }
  })

export type ProvenanceEntry = z.infer<typeof ProvenanceEntry>
export type ResourceLink = z.infer<typeof ResourceLink>
export type SpecReference = z.infer<typeof SpecReference>
export type MetadataRecord = z.infer<typeof MetadataRecord>

/** Fields a source adapter may own; everything else is reviewer-only. */
export const SOURCE_OWNED_FIELDS = [
  'name',
  'description',
  'homepage',
  'documentation',
  'categories',
  'tags',
  'capabilities',
] as const

export type SourceOwnedField = (typeof SOURCE_OWNED_FIELDS)[number]
