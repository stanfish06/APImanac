import { randomUUID } from 'node:crypto'
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js'
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js'
import { z } from 'zod'
import { GrantStore } from './auth/grants'
import { type CatalogRoot, resolveCatalogRoot } from './catalog/root'
import { callApi, type CallOutcome } from './execute/call'
import { ResponseCache } from './execute/cache'
import { ApprovalTokens, type ConfirmationChannel } from './execute/confirm'
import { HealthStore } from './execute/health'
import { MCP_PIN } from './mcp-pin'
import { matchesPattern } from './policy/permissions'
import { parsePermissionPattern } from './schema/pattern'
import { DEFAULT_LIMIT, MAX_LIMIT } from './search/constants'
import { localFacts } from './search/facts'
import { CatalogQuery, validateFilters } from './search/query'
import { showRecord } from './search/show'
import { openStore } from './store/open'
import {
  AUTH_TYPES,
  CURATION_STATES,
  CREDENTIAL_READINESS,
  HEALTH_STATES,
  LIFECYCLE_STATES,
  RESPONSE_MODES,
  VERIFICATION_STATES,
} from './schema/vocab'

/**
 * The MCP surface: stdio, exactly three tools, and no remote listener. Tool
 * input schemas come from the same Zod declarations the server validates
 * against, so the advertised contract cannot drift from what is enforced.
 */

export const TOOL_NAMES = ['search_apis', 'get_api', 'call_api'] as const

export const MAX_SEARCH_LIMIT = MAX_LIMIT
export const DEFAULT_SEARCH_LIMIT = DEFAULT_LIMIT

export interface McpOptions {
  readonly grantsPath?: string
  readonly storePath?: string
  readonly healthPath?: string
  readonly cacheDir?: string
}

export const SearchInput = {
  query: z.string().describe('Free text, or an exact canonical id or alias.'),
  limit: z.number().int().positive().optional().describe(`At most ${MAX_SEARCH_LIMIT}.`),
  curation: z.enum(CURATION_STATES).optional(),
  lifecycle: z.enum(LIFECYCLE_STATES).optional(),
  readiness: z.enum(CREDENTIAL_READINESS).optional(),
  auth_type: z.enum(AUTH_TYPES).optional(),
  health: z.enum(HEALTH_STATES).optional(),
  verification: z.enum(VERIFICATION_STATES).optional(),
  source: z.string().optional(),
  category: z.string().optional(),
  tag: z.string().optional(),
}

export const GetApiInput = {
  api: z.string().describe('Canonical id or any recorded alias.'),
  profile: z.string().optional(),
  operation: z
    .string()
    .optional()
    .describe('A method and path, or a path, to scope the result to.'),
}

/**
 * No approval token, approval flag, or consent field exists here. Confirmation
 * is carried by elicitation inside the invocation, never by a value a model can
 * supply or repeat.
 */
export const CallApiInput = {
  api: z.string(),
  profile: z.string().optional(),
  account: z.string().optional(),
  method: z.string().default('GET'),
  path: z.string().describe('Slash-prefixed relative path. Query parameters go in `query`.'),
  query: z.record(z.string(), z.string()).optional(),
  headers: z.record(z.string(), z.string()).optional(),
  body_json: z.unknown().optional(),
  body_text: z.string().optional(),
  body_form: z.record(z.string(), z.string()).optional(),
  response_mode: z.enum(RESPONSE_MODES).default('inline'),
}

const APPROVAL_SHAPED = /token|approv|consent|confirm/i

/** No advertised `call_api` input may read as an approval channel. */
export function callApiInputIsApprovalFree(): boolean {
  return !Object.keys(CallApiInput).some((name) => APPROVAL_SHAPED.test(name))
}

function textResult(payload: unknown, isError = false) {
  return {
    content: [{ type: 'text' as const, text: JSON.stringify(payload, null, 2) }],
    isError,
  }
}

/** Trims a search result to the compact summary the tool advertises. */
function summarize(result: ReturnType<CatalogQuery['search']>['results'][number]) {
  return {
    id: result.id,
    name: result.name,
    description: result.description,
    categories: result.categories,
    tags: result.tags,
    sources: result.sources,
    curation: result.curation,
    lifecycle: result.lifecycle,
    verification: result.verification,
    readiness: result.readiness,
    health: result.health,
    auth_supported: result.auth_supported,
    draft: result.draft,
    matched_alias: result.matched_alias,
    redirected_from: result.redirected_from,
  }
}

/**
 * Whether an elicitation response is consent. Fail closed: only `accept`
 * carrying a literal `true` on the required field approves, so an accept with
 * no content, a null, or a non-boolean is a decline.
 */
export function elicitationApproved(response: { action: string; content?: unknown }): boolean {
  if (response.action !== 'accept') return false
  const content = response.content as { send?: unknown } | undefined
  return content?.send === true
}

/**
 * Elicitation is the only MCP confirmation path. The server asks during the
 * call, awaits the client's action, and on accept mints the process-internal
 * token and executes within the same invocation.
 */
function elicitationChannel(server: McpServer): ConfirmationChannel | undefined {
  const capabilities = server.server.getClientCapabilities()
  if (!capabilities?.elicitation) return undefined
  return {
    label: 'mcp-elicitation',
    async confirm(preview) {
      const response = await server.server.elicitInput({
        message: `APImanac wants to send this request:\n\n${preview.summary}\n\nSend it?`,
        requestedSchema: {
          type: 'object',
          properties: {
            send: {
              type: 'boolean',
              title: 'Send this request',
              description: 'Confirm that APImanac may send exactly the request shown above.',
            },
          },
          required: ['send'],
        },
      })
      return elicitationApproved(response)
    },
  }
}

/**
 * A fresh Git context per tool invocation. `GitContext` resolves `HEAD` when it
 * opens, so a server that captured one at startup would keep comparing against
 * the commit it launched on — fail-closed, but a reviewer's commit would not
 * take effect until restart.
 */
function currentRoot(root: CatalogRoot): CatalogRoot {
  const resolution = resolveCatalogRoot(root.path)
  return resolution.ok ? resolution : root
}

export function buildServer(root: CatalogRoot, options: McpOptions = {}): McpServer {
  const server = new McpServer(
    { name: 'apimanac', version: '0.0.0' },
    { capabilities: { tools: {} } },
  )
  const sessionId = `mcp:${process.pid}:${randomUUID()}`
  const tokens = new ApprovalTokens(sessionId)

  const openHealth = () => HealthStore.open(options.healthPath)

  server.registerTool(
    'search_apis',
    {
      title: 'Search the APImanac catalog',
      description:
        'Search APIs by free text or an exact id or alias. Returns compact labeled summaries with no endpoint list, specification body, or credential material.',
      inputSchema: SearchInput,
    },
    async (input) => {
      const live = currentRoot(root)
      const health = openHealth()
      const grants = GrantStore.load({ path: options.grantsPath })
      const opened = openStore(live, { storePath: options.storePath })
      try {
        const filters = validateFilters({
          curation: input.curation,
          lifecycle: input.lifecycle,
          readiness: input.readiness,
          auth_type: input.auth_type,
          health: input.health,
          verification: input.verification,
          source: input.source,
          category: input.category,
          tag: input.tag,
        })
        const catalog = new CatalogQuery(opened.db, localFacts(live, grants, health))
        // The server clamps the limit and reports the one it applied.
        const requested = input.limit ?? DEFAULT_SEARCH_LIMIT
        const limit = Math.min(Math.max(1, requested), MAX_SEARCH_LIMIT)
        const found = catalog.search(input.query, { filters, limit })
        return textResult({
          results: found.results.map(summarize),
          applied_limit: limit,
          requested_limit: requested,
          total_matches: found.total,
          more_matches: found.more,
        })
      } catch (error) {
        return textResult({ error: (error as Error).message }, true)
      } finally {
        opened.close()
        health.close()
      }
    },
  )

  server.registerTool(
    'get_api',
    {
      title: 'Inspect one API',
      description:
        'Return metadata, profile candidates with verification state, permission decisions, local credential readiness, health, and bounded operation information. A large specification returns a bounded summary and a reference.',
      inputSchema: GetApiInput,
    },
    async (input) => {
      const live = currentRoot(root)
      const health = openHealth()
      const grants = GrantStore.load({ path: options.grantsPath })
      try {
        const record = showRecord(live, input.api, { grants, health })
        if (!record) {
          return textResult(
            {
              error: 'not_found',
              message: `\`${input.api}\` is neither a canonical id nor an alias`,
            },
            true,
          )
        }
        let profiles = record.profiles
        if (input.profile) profiles = profiles.filter((entry) => entry.profile_id === input.profile)
        if (input.operation) {
          const [maybeMethod, maybePath] = input.operation.split(/\s+/, 2)
          const path = maybePath ?? maybeMethod ?? ''
          const method = maybePath ? (maybeMethod as string).toUpperCase() : undefined
          // The selector is a concrete operation, matched by the same
          // segment-aware rules the executor uses — not a prefix search.
          profiles = profiles.map((entry) => ({
            ...entry,
            operations: entry.operations.filter((operation) => {
              if (method && operation.method !== method && operation.method !== '*') return false
              try {
                return matchesPattern(parsePermissionPattern(operation.path), path)
              } catch {
                return false
              }
            }),
          }))
        }
        return textResult({ ...record, profiles })
      } finally {
        health.close()
      }
    },
  )

  server.registerTool(
    'call_api',
    {
      title: 'Call an API through a verified profile',
      description:
        'Send a bounded request through a committed, verified execution profile. A `confirm` operation is confirmed by elicitation inside this invocation; there is no approval input.',
      inputSchema: CallApiInput,
    },
    async (input) => {
      const live = currentRoot(root)
      const health = openHealth()
      const grants = GrantStore.load({ path: options.grantsPath })
      const cache = ResponseCache.open({ directory: options.cacheDir })
      try {
        const outcome = await callApi(
          {
            root: live,
            api: input.api,
            profile: input.profile,
            account: input.account,
            method: input.method,
            path: input.path,
            query: input.query,
            headers: input.headers,
            responseMode: input.response_mode,
            body:
              input.body_json !== undefined
                ? { kind: 'json', value: input.body_json }
                : input.body_text !== undefined
                  ? { kind: 'text', value: input.body_text }
                  : input.body_form !== undefined
                    ? { kind: 'form', value: input.body_form }
                    : undefined,
          },
          {
            grants,
            health,
            cache,
            tokens,
            channel: elicitationChannel(server),
            confirmationHint:
              'this client did not negotiate elicitation, so a `confirm` operation is unavailable through MCP; run `apimanac call` on a controlling terminal',
          },
        )
        return textResult(publicOutcome(outcome), outcome.kind !== 'success')
      } finally {
        cache.close()
        health.close()
      }
    },
  )

  return server
}

/** Result variants a caller sees. No token or resumable approval handle exists. */
export function publicOutcome(outcome: CallOutcome): Record<string, unknown> {
  return {
    outcome: outcome.kind,
    message: outcome.message,
    api_id: outcome.api_id,
    profile_id: outcome.profile_id,
    decision: outcome.decision,
    request: outcome.request,
    status: outcome.status,
    headers: outcome.headers,
    body: outcome.body,
    body_encoding: outcome.body_encoding,
    file: outcome.file,
    bytes: outcome.bytes,
    from_cache: outcome.from_cache,
    candidates: outcome.candidates,
    profiles: outcome.profiles,
    missing_components: outcome.missing_components,
    preview: outcome.preview,
    remote_content: outcome.remote_content ? true : undefined,
    resolved_alias: outcome.resolved_alias,
    redirected_from: outcome.redirected_from,
    protocol_revision: MCP_PIN.protocolRevision,
  }
}

export async function startMcpServer(root: CatalogRoot, options: McpOptions = {}): Promise<void> {
  const server = buildServer(root, options)
  // stdio only: no network listener is ever opened.
  await server.connect(new StdioServerTransport())
}
