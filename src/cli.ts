#!/usr/bin/env bun
import { randomUUID } from 'node:crypto'
import { GrantStore } from './auth/grants'
import { authStatus, formatAuthStatus } from './auth/status'
import { loadWorkingTree } from './catalog/load'
import { type CatalogRoot, ROOT_PRECEDENCE, resolveCatalogRoot } from './catalog/root'
import { formatFinding, validateCatalog } from './catalog/validate'
import { ApimanacError, asApimanacError, EXIT_CODES, type ExitCode } from './errors'
import { ResponseCache } from './execute/cache'
import { type CallOutcome, callApi } from './execute/call'
import { ApprovalTokens, ScriptApprovals, ttyChannel } from './execute/confirm'
import { HealthStore } from './execute/health'
import { verifyProfile } from './execute/verify'
import { runScript, runWorkflow, type WorkflowRunOutcome } from './execute/workflow'
import { runAdd, runMigrate, runRefresh } from './maintenance/commands'
import type { ResponseMode } from './schema/vocab'
import { DEFAULT_LIMIT, MAX_LIMIT } from './search/constants'
import { localFacts } from './search/facts'
import { CatalogQuery, validateFilters } from './search/query'
import { formatShownRecord, showRecord } from './search/show'
import { buildStore } from './store/build'
import { openStore, storePathFor } from './store/open'

/**
 * The v0 command surface. Every command resolves exactly one catalog root by
 * the fixed precedence and writes machine-readable output to stdout with no
 * progress text interleaved.
 */

export const COMMANDS = [
  'build',
  'search',
  'show',
  'add',
  'refresh',
  'validate',
  'migrate',
  'auth status',
  'call',
  'verify',
  'workflow run',
  'script run',
  'cache list',
  'cache clear',
  'cache prune',
  'mcp',
] as const

export type CommandName = (typeof COMMANDS)[number]

export interface Argv {
  readonly command: CommandName
  readonly positional: string[]
  readonly flags: Record<string, string | boolean | string[]>
}

export interface Io {
  out(text: string): void
  err(text: string): void
}

const defaultIo: Io = {
  out: (text) => process.stdout.write(`${text}\n`),
  err: (text) => process.stderr.write(`${text}\n`),
}

/** Per-command flags and arguments, so `apimanac <command> --help` is useful. */
export const COMMAND_USAGE: Record<CommandName, string> = {
  build:
    'build [--offline] [--store <path>]\n  Validate the catalog and rebuild the derived store. Opens no connection.',
  search:
    'search <text…> [--limit <n>] [--curation|--lifecycle|--readiness|--auth-type|--health-state|--verification|--source|--category|--tag <value>]\n  Ranked search over the working tree. An exact id or alias short-circuits to the top.',
  show: 'show <api-id-or-alias>\n  Profiles, permissions, contract hash, authority fingerprint, readiness, health.',
  add: 'add <url> [--id <canonical-id>] [--force]\n  add --manual <name> [--id <id>] [--name <name>] [--description <text>] [--force]\n  Writes uncommitted candidates. Refuses an id the catalog already holds unless --force.',
  refresh:
    'refresh <public-apis|nango|apis-guru> --payload <path> --pin <path> [--scopes <path>] [--specs <dir>]\n  refresh --candidate <path>\n  Adapters take already-fetched input. --specs holds one file per upstream list id (`/` written as `__`).',
  validate: 'validate\n  Every integrity check, no network. Reports all findings, not the first.',
  migrate:
    'migrate\n  Deterministic schema step. Validates before writing; leaves an uncommitted diff.',
  'auth status':
    'auth status [--grants <path>]\n  Read-only, offline. Names components, never values, variables, or paths.',
  call: 'call <api-id-or-alias> --path </relative/path> [--method <VERB>] [--profile <id>] [--account <name>]\n       [--query name=value …] [--header name=value …] [--body <text>] [--response inline|file] [--origin <origin>]\n  --query and --header repeat. A `confirm` operation needs a controlling terminal.',
  verify:
    'verify <api-id> --profile <profile> [--account <name>]\n  The only path from candidate to verified. Always prompts; refuses without a terminal.',
  'workflow run':
    'workflow run <api-id>/<workflow-id> [--params <json>] [--grants <path>] [--cache-dir <path>]\n  Run a committed, pinned workflow. Params are validated against its declared schema.\n  A `confirm` operation prompts on the controlling terminal, one request at a time.',
  'script run':
    'script run <file.ts> --bind <api-id>/<profile-id> [--bind …] [--params <json>]\n  Run an uncommitted script after approving its full source on the controlling terminal.\n  The script can call only the bound profiles; per-operation policy still applies.',
  'cache list':
    'cache list [--cache-dir <path>]\n  Sanitized origin, path and account labels only.',
  'cache clear': 'cache clear [--cache-dir <path>]\n  Remove every cached response.',
  'cache prune': 'cache prune [--cache-dir <path>]\n  Remove expired entries and shrink to quota.',
  mcp: 'mcp [--grants <path>] [--store <path>] [--health <path>] [--cache-dir <path>]\n  stdio MCP server: search_apis, get_api, call_api, run_workflow, run_script. Opens no listener.',
}

export function usageFor(command: CommandName): string {
  return `apimanac ${COMMAND_USAGE[command]}\n\nGlobal: --catalog <path>  --json`
}

export const USAGE = `apimanac — a reviewed catalog of APIs an agent can search, inspect, and call

Usage: apimanac [--catalog <path>] [--json] <command> [options]

Commands:
${COMMANDS.map((name) => `  ${name}`).join('\n')}

The catalog root is resolved by ${ROOT_PRECEDENCE}.
The working directory never influences resolution.

A \`confirm\` operation requires a controlling terminal. No flag or environment
value approves a call.`

/** Flags that never take a value, so a following word stays positional. */
const BOOLEAN_FLAGS = new Set(['json', 'offline', 'manual', 'help'])

function parseFlagValue(
  token: string,
  next: string | undefined,
): [string, string | boolean, number] {
  const body = token.slice(2)
  const equals = body.indexOf('=')
  if (equals >= 0) return [body.slice(0, equals), body.slice(equals + 1), 0]
  if (BOOLEAN_FLAGS.has(body)) return [body, true, 0]
  if (next !== undefined && !next.startsWith('--')) return [body, next, 1]
  return [body, true, 0]
}

/** Flags whose every occurrence is kept, collected under `<name>[]`. */
const REPEATABLE_FLAGS = new Set(['query', 'header', 'bind'])

export function parseArgs(argv: readonly string[]): Argv {
  const flags: Record<string, string | boolean | string[]> = {}
  const words: string[] = []
  for (let i = 0; i < argv.length; i++) {
    const token = argv[i] as string
    if (token.startsWith('--')) {
      const [name, value, consumed] = parseFlagValue(token, argv[i + 1])
      if (REPEATABLE_FLAGS.has(name) && typeof value === 'string') {
        const collected = (flags[`${name}[]`] as string[] | undefined) ?? []
        collected.push(value)
        flags[`${name}[]`] = collected
      }
      flags[name] = value as string | boolean
      i += consumed
      continue
    }
    words.push(token)
  }

  const two = words.slice(0, 2).join(' ')
  if ((COMMANDS as readonly string[]).includes(two)) {
    return { command: two as CommandName, positional: words.slice(2), flags }
  }
  const one = words[0]
  if (one !== undefined && (COMMANDS as readonly string[]).includes(one)) {
    return { command: one as CommandName, positional: words.slice(1), flags }
  }
  throw new ApimanacError(
    'unknown_command',
    one === undefined ? 'no command given' : `unknown command \`${words.join(' ')}\``,
    { commands: [...COMMANDS] },
  )
}

export function requireRoot(flags: Record<string, string | boolean | string[]>): CatalogRoot {
  const argument = typeof flags.catalog === 'string' ? flags.catalog : undefined
  const resolution = resolveCatalogRoot(argument)
  if (!resolution.ok) {
    throw new ApimanacError('catalog_root_unresolved', resolution.message, {
      code: resolution.code,
      precedence: ROOT_PRECEDENCE,
      path: resolution.path,
    })
  }
  return resolution
}

interface CommandContext {
  readonly argv: Argv
  readonly io: Io
  readonly json: boolean
}

type Handler = (context: CommandContext) => Promise<unknown> | unknown

function flagString(
  flags: Record<string, string | boolean | string[]>,
  name: string,
): string | undefined {
  const value = flags[name]
  return typeof value === 'string' ? value : undefined
}

/**
 * Repeatable `--query name=value` / `--header name=value` pairs. Each occurrence
 * is one pair, so a value containing a comma is preserved verbatim.
 */
function pairs(
  flags: Record<string, string | boolean | string[]>,
  name: string,
): Record<string, string> {
  const out: Record<string, string> = {}
  for (const entry of (flags[`${name}[]`] as string[] | undefined) ?? []) {
    const equals = entry.indexOf('=')
    if (equals <= 0) {
      throw new ApimanacError('usage', `--${name} takes name=value, got \`${entry}\``)
    }
    out[entry.slice(0, equals)] = entry.slice(equals + 1)
  }
  return out
}

function runValidate({ argv, io, json }: CommandContext): unknown {
  const root = requireRoot(argv.flags)
  const report = validateCatalog(loadWorkingTree(root.path, root.git), root.git)
  if (report.ok) {
    if (json) return { catalog_root: root.path, ok: true, findings: [] }
    io.out(`${root.path}: no findings`)
    return undefined
  }
  if (!json) for (const finding of report.findings) io.out(formatFinding(finding))
  throw new ApimanacError('validation_failed', `${report.findings.length} finding(s)`, {
    catalog_root: root.path,
    findings: report.findings,
  })
}

function runBuild({ argv, io, json }: CommandContext): unknown {
  const root = requireRoot(argv.flags)
  const storePath = flagString(argv.flags, 'store') ?? storePathFor()
  // The build never opens a connection. `--offline` asserts that rather than
  // switching it: it fails if the root has no reviewed snapshot to build from.
  const offline = argv.flags.offline === true || argv.flags.offline === 'true'
  if (offline && !root.git.available) {
    throw new ApimanacError(
      'catalog_root_unresolved',
      `--offline needs a reviewed snapshot: ${root.noSnapshotReason ?? 'the root has none'}`,
      { catalog_root: root.path },
    )
  }
  const result = buildStore(root, { storePath })
  if (json) return { catalog_root: root.path, offline, ...result }
  io.out(
    `built ${result.path}: ${result.discoveryRecords} discovery record(s), ${result.authorityRecords} authority record(s), ${result.indexRows} index row(s)`,
  )
  return undefined
}

function services(root: CatalogRoot, argv: Argv) {
  const grants = GrantStore.load({ path: flagString(argv.flags, 'grants') })
  const health = HealthStore.open(flagString(argv.flags, 'health'))
  return { grants, health, root }
}

function runSearch({ argv, io, json }: CommandContext): unknown {
  const root = requireRoot(argv.flags)
  const { grants, health } = services(root, argv)
  const filters = validateFilters({
    curation: flagString(argv.flags, 'curation'),
    lifecycle: flagString(argv.flags, 'lifecycle'),
    readiness: flagString(argv.flags, 'readiness'),
    auth_type: flagString(argv.flags, 'auth-type'),
    health: flagString(argv.flags, 'health-state'),
    verification: flagString(argv.flags, 'verification'),
    source: flagString(argv.flags, 'source'),
    category: flagString(argv.flags, 'category'),
    tag: flagString(argv.flags, 'tag'),
  })
  const opened = openStore(root, { storePath: flagString(argv.flags, 'store') })
  try {
    const catalog = new CatalogQuery(opened.db, localFacts(root, grants, health))
    // Clamped exactly as the MCP tool clamps, so the two surfaces agree.
    const requested = Number(flagString(argv.flags, 'limit') ?? '') || DEFAULT_LIMIT
    const limit = Math.min(Math.max(1, requested), MAX_LIMIT)
    const result = catalog.search(argv.positional.join(' '), { filters, limit })
    if (json) return result
    if (result.results.length === 0) io.out('no matching record')
    for (const entry of result.results) {
      io.out(
        `${entry.id.padEnd(20)} ${entry.curation}/${entry.lifecycle}${entry.draft ? '/draft' : ''}  ${entry.readiness}  ${entry.health}  ${entry.name}`,
      )
      if (entry.matched_alias) io.out(`  (matched alias ${entry.matched_alias})`)
      if (entry.redirected_from) io.out(`  (redirected from ${entry.redirected_from})`)
      if (entry.description) io.out(`  ${entry.description}`)
    }
    if (result.more) io.out(`…${result.total - result.results.length} more match(es)`)
    return undefined
  } finally {
    opened.close()
    health.close()
  }
}

function runShow({ argv, io, json }: CommandContext): unknown {
  const root = requireRoot(argv.flags)
  const requested = argv.positional[0]
  if (!requested) throw new ApimanacError('usage', 'show needs an API id or alias')
  const { grants, health } = services(root, argv)
  try {
    const record = showRecord(root, requested, { grants, health })
    if (!record) {
      throw new ApimanacError(
        'not_found',
        `\`${requested}\` is neither a canonical id nor an alias`,
        {
          requested,
        },
      )
    }
    if (json) return record
    io.out(formatShownRecord(record))
    return undefined
  } finally {
    health.close()
  }
}

function runAuthStatus({ argv, io, json }: CommandContext): unknown {
  const root = requireRoot(argv.flags)
  const report = authStatus(root, { path: flagString(argv.flags, 'grants') })
  if (json) return report
  io.out(formatAuthStatus(report))
  return undefined
}

async function runCall({ argv, io, json }: CommandContext): Promise<unknown> {
  const root = requireRoot(argv.flags)
  const api = argv.positional[0]
  if (!api) throw new ApimanacError('usage', 'call needs an API id or alias')
  const path = flagString(argv.flags, 'path')
  if (!path) throw new ApimanacError('usage', 'call needs --path </relative/path>')
  const { grants, health } = services(root, argv)
  const cache = ResponseCache.open({ directory: flagString(argv.flags, 'cache-dir') })
  const bodyText = flagString(argv.flags, 'body')
  const bodyKind = flagString(argv.flags, 'body-kind')
  try {
    const outcome = await callApi(
      {
        root,
        api,
        profile: flagString(argv.flags, 'profile'),
        account: flagString(argv.flags, 'account'),
        method: flagString(argv.flags, 'method') ?? 'GET',
        path,
        query: pairs(argv.flags, 'query'),
        headers: pairs(argv.flags, 'header'),
        origin: flagString(argv.flags, 'origin'),
        responseMode: (flagString(argv.flags, 'response') as ResponseMode | undefined) ?? 'inline',
        body: bodyText ? { kind: 'text', value: bodyText } : undefined,
        bodyKind,
      },
      {
        grants,
        health,
        cache,
        tokens: new ApprovalTokens(`cli:${process.pid}:${randomUUID()}`),
        // Only a controlling terminal can confirm; no flag substitutes for it.
        channel: ttyChannel(),
        confirmationHint:
          'this operation requires an interactive confirmation; run `apimanac call` yourself on a controlling terminal',
      },
    )
    return emitCall(outcome, io, json)
  } finally {
    cache.close()
    health.close()
  }
}

function emitCall(outcome: CallOutcome, io: Io, json: boolean): unknown {
  if (outcome.kind === 'success' || outcome.kind === 'remote_response') {
    if (json) return outcome
    io.out(
      `${outcome.status} ${outcome.from_cache ? '(cached) ' : ''}${outcome.bytes ?? 0} byte(s)`,
    )
    if (outcome.file) io.out(`saved ${outcome.file.path} (${outcome.file.media_type})`)
    else if (outcome.body) io.out(outcome.body)
    if (outcome.kind === 'remote_response') {
      throw new ApimanacError('remote_error_status', outcome.message, {
        status: outcome.status,
        remote_content: true,
      })
    }
    return undefined
  }
  throw new ApimanacError(callErrorKind(outcome.kind), outcome.message, {
    outcome: outcome.kind,
    api_id: outcome.api_id,
    profile_id: outcome.profile_id,
    candidates: outcome.candidates,
    profiles: outcome.profiles,
    missing_components: outcome.missing_components,
    preview: outcome.preview,
  })
}

function callErrorKind(kind: CallOutcome['kind']) {
  switch (kind) {
    case 'denied':
      return 'operation_denied' as const
    case 'ineligible':
      return 'profile_ineligible' as const
    case 'confirmation_required':
      return 'confirmation_required' as const
    case 'confirmation_declined':
      return 'confirmation_declined' as const
    case 'missing_grant':
      return 'missing_grant' as const
    case 'missing_credential':
      return 'missing_credential' as const
    case 'unsupported_auth':
      return 'unsupported_auth' as const
    case 'unsupported_request':
      return 'unsupported_request' as const
    case 'ambiguous_profile':
      return 'ambiguous_profile' as const
    case 'ambiguous_account':
      return 'ambiguous_account' as const
    case 'credential_echo_detected':
      return 'credential_echo_detected' as const
    case 'network_failure':
      return 'transport_failed' as const
    case 'not_found':
      return 'not_found' as const
    default:
      return 'policy_refused' as const
  }
}

function parseParamsFlag(flags: Record<string, string | boolean | string[]>): unknown {
  const raw = flagString(flags, 'params')
  if (raw === undefined) return undefined
  try {
    return JSON.parse(raw)
  } catch (error) {
    throw new ApimanacError('usage', `--params is not valid JSON: ${(error as Error).message}`)
  }
}

function runServices() {
  const session = `cli:${process.pid}:${randomUUID()}`
  return {
    tokens: new ApprovalTokens(session),
    scriptApprovals: new ScriptApprovals(session),
    // Only a controlling terminal can confirm; no flag substitutes for it.
    channel: ttyChannel(),
  }
}

function emitRun(outcome: WorkflowRunOutcome, io: Io, json: boolean): unknown {
  if (outcome.kind === 'success') {
    if (json) return outcome
    io.out(`completed after ${outcome.calls} call(s)`)
    io.out(JSON.stringify(outcome.result, null, 2))
    if (outcome.stderr) io.err(`script stderr (untrusted):\n${outcome.stderr}`)
    return undefined
  }
  throw new ApimanacError(runErrorKind(outcome.kind), outcome.message, {
    outcome: outcome.kind,
    api_id: outcome.api_id,
    workflow_id: outcome.workflow_id,
    reasons: outcome.reasons,
    issues: outcome.issues,
    calls: outcome.calls,
    stderr: outcome.stderr,
  })
}

function runErrorKind(kind: WorkflowRunOutcome['kind']) {
  switch (kind) {
    case 'invalid_params':
      return 'unsupported_request' as const
    case 'ineligible':
      return 'profile_ineligible' as const
    case 'approval_required':
      return 'confirmation_required' as const
    case 'approval_declined':
      return 'confirmation_declined' as const
    case 'sandbox_unavailable':
      return 'unsupported_request' as const
    default:
      return 'policy_refused' as const
  }
}

async function runWorkflowCmd({ argv, io, json }: CommandContext): Promise<unknown> {
  const root = requireRoot(argv.flags)
  const target = argv.positional[0]
  const separator = target?.indexOf('/') ?? -1
  if (!target || separator <= 0 || separator === target.length - 1) {
    throw new ApimanacError('usage', 'workflow run needs <api-id>/<workflow-id>')
  }
  const { grants, health } = services(root, argv)
  const cache = ResponseCache.open({ directory: flagString(argv.flags, 'cache-dir') })
  try {
    const outcome = await runWorkflow(
      {
        root,
        api: target.slice(0, separator),
        workflow: target.slice(separator + 1),
        params: parseParamsFlag(argv.flags),
      },
      {
        grants,
        health,
        cache,
        ...runServices(),
        confirmationHint:
          'this operation requires an interactive confirmation; run `apimanac workflow run` yourself on a controlling terminal',
      },
    )
    return emitRun(outcome, io, json)
  } finally {
    cache.close()
    health.close()
  }
}

async function runScriptCmd({ argv, io, json }: CommandContext): Promise<unknown> {
  const root = requireRoot(argv.flags)
  const file = argv.positional[0]
  if (!file) throw new ApimanacError('usage', 'script run needs a <file.ts> path')
  const bindings = (argv.flags['bind[]'] as string[] | undefined) ?? []
  if (bindings.length === 0) {
    throw new ApimanacError('usage', 'script run needs at least one --bind <api-id>/<profile-id>')
  }
  let source: string
  try {
    source = await Bun.file(file).text()
  } catch (error) {
    throw new ApimanacError('usage', `could not read \`${file}\`: ${(error as Error).message}`)
  }
  const { grants, health } = services(root, argv)
  const cache = ResponseCache.open({ directory: flagString(argv.flags, 'cache-dir') })
  try {
    const outcome = await runScript(
      { root, source, bindings, params: parseParamsFlag(argv.flags) },
      {
        grants,
        health,
        cache,
        ...runServices(),
        confirmationHint:
          'an ad-hoc script requires approving its full source; run `apimanac script run` yourself on a controlling terminal',
      },
    )
    return emitRun(outcome, io, json)
  } finally {
    cache.close()
    health.close()
  }
}

async function runVerify({ argv, io, json }: CommandContext): Promise<unknown> {
  const root = requireRoot(argv.flags)
  const api = argv.positional[0]
  const profile = flagString(argv.flags, 'profile')
  if (!api || !profile) {
    throw new ApimanacError('usage', 'verify needs an API id and --profile <profile>')
  }
  const { grants, health } = services(root, argv)
  try {
    const outcome = await verifyProfile(
      { root, api, profile, account: flagString(argv.flags, 'account') },
      { grants, health, channel: ttyChannel() },
    )
    if (json) return outcome
    if (outcome.kind === 'verified') {
      io.out(outcome.message)
      io.out(`contract hash:         ${outcome.contract_hash}`)
      io.out(`authority fingerprint: ${outcome.authority_fingerprint}`)
      return undefined
    }
    throw new ApimanacError(
      outcome.kind === 'no_terminal' ? 'confirmation_required' : 'policy_refused',
      outcome.message,
      { outcome: outcome.kind, file: outcome.file },
    )
  } finally {
    health.close()
  }
}

function withCache<T>(argv: Argv, run: (cache: ResponseCache) => T): T {
  const cache = ResponseCache.open({ directory: flagString(argv.flags, 'cache-dir') })
  try {
    return run(cache)
  } finally {
    cache.close()
  }
}

function runCacheList({ argv, io, json }: CommandContext): unknown {
  return withCache(argv, (cache) => {
    const entries = cache.list()
    if (json) return { entries, bytes: cache.bytes }
    for (const entry of entries) {
      io.out(
        `${entry.profile.padEnd(24)} ${entry.origin}${entry.path}  ${entry.account ?? '-'}  ${entry.bytes}B  expires ${entry.expires_at}`,
      )
    }
    if (entries.length === 0) io.out('the response cache is empty')
    return undefined
  })
}

function runCacheClear({ argv, io, json }: CommandContext): unknown {
  return withCache(argv, (cache) => {
    const removed = cache.clear()
    if (json) return { removed }
    io.out(`removed ${removed} cache entr${removed === 1 ? 'y' : 'ies'}`)
    return undefined
  })
}

function runCachePrune({ argv, io, json }: CommandContext): unknown {
  return withCache(argv, (cache) => {
    const result = cache.prune()
    if (json) return result
    io.out(
      `pruned ${result.expired} expired and evicted ${result.evicted}; ${result.bytes}B remain`,
    )
    return undefined
  })
}

async function runMcp({ argv }: CommandContext): Promise<unknown> {
  const root = requireRoot(argv.flags)
  const { startMcpServer } = await import('./mcp')
  await startMcpServer(root, {
    grantsPath: flagString(argv.flags, 'grants'),
    storePath: flagString(argv.flags, 'store'),
    healthPath: flagString(argv.flags, 'health'),
    cacheDir: flagString(argv.flags, 'cache-dir'),
  })
  return undefined
}

const HANDLERS: Record<CommandName, Handler> = {
  build: runBuild,
  validate: runValidate,
  search: runSearch,
  show: runShow,
  add: ({ argv, io, json }) => runAdd(requireRoot(argv.flags), argv, io, json),
  refresh: ({ argv, io, json }) => runRefresh(requireRoot(argv.flags), argv, io, json),
  migrate: ({ argv, io, json }) => runMigrate(requireRoot(argv.flags), argv, io, json),
  'auth status': runAuthStatus,
  call: runCall,
  verify: runVerify,
  'workflow run': runWorkflowCmd,
  'script run': runScriptCmd,
  'cache list': runCacheList,
  'cache clear': runCacheClear,
  'cache prune': runCachePrune,
  mcp: runMcp,
}

export async function runCli(argv: readonly string[], io: Io = defaultIo): Promise<ExitCode> {
  const wantsHelp = argv.includes('--help') || argv.includes('-h')
  if (argv.length === 0) {
    io.out(USAGE)
    return EXIT_CODES.ok
  }
  if (wantsHelp) {
    // `apimanac <command> --help` documents that command, not the whole surface.
    const named = argv.filter((token) => !token.startsWith('-'))
    let command: CommandName | undefined
    try {
      command = parseArgs(named).command
    } catch {
      command = undefined
    }
    io.out(command ? usageFor(command) : USAGE)
    return EXIT_CODES.ok
  }
  let json = false
  try {
    const parsed = parseArgs(argv)
    json = parsed.flags.json === true || parsed.flags.json === 'true'
    const result = await HANDLERS[parsed.command]({ argv: parsed, io, json })
    if (json) io.out(JSON.stringify(result ?? { ok: true }, null, 2))
    return EXIT_CODES.ok
  } catch (error) {
    const failure = asApimanacError(error)
    if (json) io.out(JSON.stringify({ ok: false, error: failure.toJSON() }, null, 2))
    else io.err(`error: ${failure.kind}: ${failure.message}`)
    return failure.exitCode
  }
}

if (import.meta.main) {
  process.exitCode = await runCli(process.argv.slice(2))
}
