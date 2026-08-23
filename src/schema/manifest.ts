import { z } from 'zod'
import { CURATION_STATES, CanonicalId, LIFECYCLE_STATES } from './vocab'

/** The one schema version this build reads and writes. */
export const SUPPORTED_SCHEMA_VERSION = 1

export const SourceDeclaration = z
  .object({
    id: CanonicalId,
    name: z.string().min(1),
    /** Repository-relative path of the source manifest. */
    manifest: z.string().min(1),
    homepage: z.string().url().optional(),
    license: z.string().min(1).optional(),
  })
  .strict()

export const RootManifest = z
  .object({
    catalog_name: z.string().min(1),
    schema_version: z.number().int().nonnegative(),
    sources: z.array(SourceDeclaration).default([]),
    lifecycle_vocabulary: z.array(z.string()).default([...LIFECYCLE_STATES]),
    curation_vocabulary: z.array(z.string()).default([...CURATION_STATES]),
  })
  .strict()
  .superRefine((value, ctx) => {
    const seen = new Set<string>()
    for (const source of value.sources) {
      if (seen.has(source.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['sources'],
          message: `duplicate source id \`${source.id}\``,
        })
      }
      seen.add(source.id)
    }
    if (!setsEqual(value.lifecycle_vocabulary, LIFECYCLE_STATES)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['lifecycle_vocabulary'],
        message: `must be exactly ${LIFECYCLE_STATES.join(', ')}`,
      })
    }
    if (!setsEqual(value.curation_vocabulary, CURATION_STATES)) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['curation_vocabulary'],
        message: `must be exactly ${CURATION_STATES.join(', ')}`,
      })
    }
  })

function setsEqual(a: readonly string[], b: readonly string[]): boolean {
  return a.length === b.length && [...a].sort().join() === [...b].sort().join()
}

export type SourceDeclaration = z.infer<typeof SourceDeclaration>
export type RootManifest = z.infer<typeof RootManifest>
