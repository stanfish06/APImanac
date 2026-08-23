import { z } from 'zod'
import { Origin, TaggedHash } from './execution'
import { CanonicalId, ComponentName } from './vocab'

/**
 * Local grants. These live outside the repository under `$XDG_CONFIG_HOME` and
 * are the only place a component name is bound to a real local value.
 */

export const EnvProvider = z
  .object({
    provider: z.literal('env'),
    /** Environment variable name. Never surfaced by any output. */
    variable: z.string().min(1),
  })
  .strict()

export const FileProvider = z
  .object({
    provider: z.literal('file'),
    /** Path under the APImanac data directory. Never surfaced by any output. */
    path: z.string().min(1),
  })
  .strict()

export const ProviderReference = z.discriminatedUnion('provider', [EnvProvider, FileProvider])

export const GrantAccount = z
  .object({
    name: z.string().min(1),
    default: z.boolean().default(false),
    components: z.record(ComponentName, ProviderReference),
  })
  .strict()

export const Grant = z
  .object({
    credential_id: z.string().min(1),
    api_id: CanonicalId,
    profile_id: CanonicalId,
    origins: z.array(Origin).min(1),
    /** The profile fingerprint the user activated this grant against. */
    authority_fingerprint: TaggedHash,
    accounts: z.array(GrantAccount).min(1),
  })
  .strict()
  .superRefine((value, ctx) => {
    const names = new Set<string>()
    let defaults = 0
    for (const account of value.accounts) {
      if (names.has(account.name)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['accounts'],
          message: `duplicate account name \`${account.name}\``,
        })
      }
      names.add(account.name)
      if (account.default) defaults += 1
      if (Object.keys(account.components).length === 0) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          path: ['accounts'],
          message: `account \`${account.name}\` binds no component`,
        })
      }
    }
    if (defaults > 1) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        path: ['accounts'],
        message: 'at most one account may be marked default',
      })
    }
  })

export const GrantsFile = z
  .object({
    version: z.number().int().positive().default(1),
    grants: z.array(Grant).default([]),
  })
  .strict()
  .superRefine((value, ctx) => {
    // A stale grant kept alongside a rebinding is expected: the fingerprint
    // tells them apart. Only two grants sharing a fingerprint AND an account
    // name are ambiguous.
    const seen = new Set<string>()
    for (const grant of value.grants) {
      for (const account of grant.accounts) {
        const key = `${grant.api_id}/${grant.profile_id}/${grant.authority_fingerprint}/${account.name}`
        if (seen.has(key)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            path: ['grants'],
            message: `account \`${account.name}\` is bound twice for ${grant.api_id}/${grant.profile_id} against the same authority fingerprint; remove the duplicate`,
          })
        }
        seen.add(key)
      }
    }
  })

export type ProviderReference = z.infer<typeof ProviderReference>
export type GrantAccount = z.infer<typeof GrantAccount>
export type Grant = z.infer<typeof Grant>
export type GrantsFile = z.infer<typeof GrantsFile>
