import { MUTATING_METHODS } from '../policy/permissions'
import { z } from 'zod'
import { ApimanacError } from '../errors'
import { BasePath, Origin, ProfileAuth } from '../schema/execution'
import { isValidPermissionPattern } from '../schema/pattern'
import { APIS_GURU_REASONS } from '../schema/reasons'
import { CANONICAL_ID_PATTERN } from '../schema/vocab'
import {
  type AdapterRun,
  aliasFor,
  assertNoVerifiedProfiles,
  compare,
  describeIssues,
  entryContentHash,
  type ExecutionCandidate,
  type MetadataCandidate,
  type SourceAdapter,
  type SourcePin,
  slugify,
  truncateDetail,
} from './adapter'

/**
 * The APIs.guru list carries discovery metadata; it never carries a server. An
 * origin only ever comes from a specification the caller already fetched, so a
 * list entry with no specification yields metadata and nothing executable.
 */

const SOURCE_ID = 'apis-guru'
const PROFILE_ID = 'apis-guru'
const MAX_PERMISSION_RULES = 50
const SUMMARY_MAX = 2000

export interface SpecLimits {
  maxBytes: number
}

export const DEFAULT_SPEC_LIMITS: SpecLimits = { maxBytes: 2_000_000 }

const GuruVersion = z
  .object({
    info: z.record(z.string(), z.unknown()).optional(),
    swaggerUrl: z.string().optional(),
    swaggerYamlUrl: z.string().optional(),
    updated: z.string().optional(),
    link: z.string().optional(),
  })
  .passthrough()

const GuruEntry = z
  .object({
    preferred: z.string().optional(),
    versions: z.record(z.string(), GuruVersion).optional(),
  })
  .passthrough()

const GuruList = z.record(z.string(), z.unknown())

type GuruVersion = z.infer<typeof GuruVersion>

interface Failure {
  reasonCode: string
  detail: string
}

function fail(reasonCode: string, detail: string): Failure {
  return { reasonCode, detail }
}

function isFailure(value: object): value is Failure {
  return 'reasonCode' in value
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

function asUrl(value: unknown): string | undefined {
  const raw = asString(value)
  if (!raw) return undefined
  try {
    const parsed = new URL(raw)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return undefined
    return parsed.toString()
  } catch {
    return undefined
  }
}

interface Servers {
  origins: string[]
  basePath?: string
}

function swagger2Servers(doc: Record<string, unknown>): Servers | Failure {
  const host = asString(doc.host)
  if (!host) return fail('no_servers_in_spec', 'swagger 2.0 document declares no `host`')
  const declared = Array.isArray(doc.schemes)
    ? doc.schemes.filter((scheme): scheme is string => typeof scheme === 'string')
    : []
  const schemes = declared.length > 0 ? declared : ['https']
  const origins: string[] = []
  for (const scheme of schemes) {
    const origin = `${scheme}://${host}`.toLowerCase()
    if (!Origin.safeParse(origin).success) {
      return fail('invalid_server_url', `\`${origin}\` is not an exact origin`)
    }
    if (!origins.includes(origin)) origins.push(origin)
  }
  const raw = asString(doc.basePath)
  if (!raw) return { origins }
  const path = raw.replace(/\/+$/, '')
  if (path === '') return { origins }
  if (!BasePath.safeParse(path).success) {
    return fail('invalid_server_url', `basePath \`${raw}\` is not a usable base path`)
  }
  return { origins, basePath: path }
}

function openapi3Servers(doc: Record<string, unknown>): Servers | Failure {
  const servers = Array.isArray(doc.servers) ? doc.servers : []
  if (servers.length === 0) return fail('no_servers_in_spec', 'document declares no `servers`')
  const origins: string[] = []
  let basePath: string | undefined
  for (const server of servers) {
    const url = asString(asRecord(server)?.url)
    if (!url) return fail('invalid_server_url', 'a `servers` entry declares no `url`')
    if (url.includes('{')) {
      return fail('invalid_server_url', `server url \`${url}\` is templated`)
    }
    let parsed: URL
    try {
      parsed = new URL(url)
    } catch {
      return fail('invalid_server_url', `server url \`${url}\` is not absolute`)
    }
    const origin = `${parsed.protocol}//${parsed.host}`.toLowerCase()
    if (!Origin.safeParse(origin).success) {
      return fail('invalid_server_url', `server url \`${url}\` does not reduce to an exact origin`)
    }
    if (!origins.includes(origin)) origins.push(origin)
    // A server path is the profile's base path, never part of its origin.
    if (basePath === undefined) {
      const path = parsed.pathname.replace(/\/+$/, '')
      if (path !== '' && BasePath.safeParse(path).success) basePath = path
    }
  }
  return basePath === undefined ? { origins } : { origins, basePath }
}

/** Read operations become `auto` rules for their literal path; everything else is denied. */
function permissionRules(doc: Record<string, unknown>): {
  rules: { method: string; path: string; decision: string }[]
  capped: boolean
} {
  const paths = asRecord(doc.paths) ?? {}
  const rules: { method: string; path: string; decision: string }[] = []
  let capped = false
  for (const key of Object.keys(paths).sort(compare)) {
    const item = asRecord(paths[key])
    if (!item) continue
    const pattern = key.replace(/\{[^}]*\}/g, '*')
    if (!pattern.startsWith('/') || !isValidPermissionPattern(pattern)) continue
    for (const method of ['get', 'head'] as const) {
      if (!(method in item)) continue
      if (rules.length >= MAX_PERMISSION_RULES) {
        capped = true
        continue
      }
      const rule = { method: method.toUpperCase(), path: pattern, decision: 'auto' }
      if (
        rules.some((existing) => existing.method === rule.method && existing.path === rule.path)
      ) {
        continue
      }
      rules.push(rule)
    }
  }
  // A wildcard-method deny would also deny the GET rules above, since a
  // matching deny always wins; only the mutating methods are denied outright.
  for (const method of MUTATING_METHODS) {
    rules.push({ method, path: '/**', decision: 'deny' })
  }
  return { rules, capped }
}

function securitySchemes(doc: Record<string, unknown>): Record<string, unknown> {
  const openapi = asRecord(asRecord(doc.components)?.securitySchemes)
  return openapi ?? asRecord(doc.securityDefinitions) ?? {}
}

/** A scheme this version cannot execute still yields a describable, non-executable auth block. */
function describableAuth(credentialId: string, type: 'oauth2' | 'custom', scopes: string[]) {
  return { type, credential_id: credentialId, components: [], placements: [], scopes }
}

function oauthScopes(scheme: Record<string, unknown>): string[] {
  const direct = asRecord(scheme.scopes)
  if (direct) return Object.keys(direct).sort(compare)
  const flows = asRecord(scheme.flows)
  if (!flows) return []
  const names = new Set<string>()
  for (const flow of Object.values(flows)) {
    for (const scope of Object.keys(asRecord(asRecord(flow)?.scopes) ?? {})) names.add(scope)
  }
  return [...names].sort(compare)
}

function buildAuth(doc: Record<string, unknown>, credentialId: string): unknown {
  const schemes = securitySchemes(doc)
  const key = Object.keys(schemes).sort(compare)[0]
  if (key === undefined) return { type: 'none' }
  const scheme = asRecord(schemes[key])
  if (!scheme) return { type: 'none' }
  const type = asString(scheme.type)?.toLowerCase()

  if (type === 'oauth2') return describableAuth(credentialId, 'oauth2', oauthScopes(scheme))
  let built: unknown
  if (type === 'apikey') {
    const name = asString(scheme.name)
    const location = asString(scheme.in)?.toLowerCase()
    if (!name || (location !== 'header' && location !== 'query')) {
      return describableAuth(credentialId, 'custom', [])
    }
    built = {
      type: location === 'header' ? 'header_key' : 'query_key',
      credential_id: credentialId,
      components: [{ name: 'key' }],
      placements: [
        location === 'header'
          ? { kind: 'header', header: name, template: '{key}' }
          : { kind: 'query', parameter: name, template: '{key}' },
      ],
    }
  } else if (type === 'basic' || (type === 'http' && asString(scheme.scheme) === 'basic')) {
    built = {
      type: 'basic',
      credential_id: credentialId,
      components: [{ name: 'username' }, { name: 'password' }],
      placements: [
        { kind: 'basic', header: 'Authorization', username: 'username', password: 'password' },
      ],
    }
  } else if (type === 'http' && asString(scheme.scheme) === 'bearer') {
    built = {
      type: 'bearer',
      credential_id: credentialId,
      components: [{ name: 'token' }],
      placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
    }
  } else {
    return describableAuth(credentialId, 'custom', [])
  }
  // A scheme naming a header or parameter the wire format forbids stays describable.
  return ProfileAuth.safeParse(built).success ? built : describableAuth(credentialId, 'custom', [])
}

interface SpecOutcome {
  profile: unknown
  specRef: Record<string, unknown>
}

function resolveSpec(
  rawId: string,
  apiId: string,
  specUrl: string,
  title: string,
  summary: string | undefined,
  value: unknown,
  limits: SpecLimits,
): SpecOutcome | Failure {
  const marker = asRecord(value)
  if (marker?.__oversized === true) {
    const size = typeof marker.byteSize === 'number' ? marker.byteSize : undefined
    return fail(
      'spec_too_large',
      `specification for \`${rawId}\` exceeds ${limits.maxBytes} bytes${size ? ` (${size})` : ''}; the fetch was aborted`,
    )
  }
  const doc = marker
  if (!doc) return fail('spec_unparseable', `specification for \`${rawId}\` is not a JSON object`)
  let byteSize: number
  try {
    byteSize = Buffer.byteLength(JSON.stringify(doc), 'utf8')
  } catch {
    return fail('spec_unparseable', `specification for \`${rawId}\` is not serializable`)
  }
  if (byteSize > limits.maxBytes) {
    return fail(
      'spec_too_large',
      `specification for \`${rawId}\` is ${byteSize} bytes, over the ${limits.maxBytes} byte limit`,
    )
  }

  const swagger = asString(doc.swagger)
  const openapi = asString(doc.openapi)
  let format: 'swagger-2' | 'openapi-3'
  let servers: Servers | Failure
  if (swagger === '2.0') {
    format = 'swagger-2'
    servers = swagger2Servers(doc)
  } else if (openapi?.startsWith('3.')) {
    format = 'openapi-3'
    servers = openapi3Servers(doc)
  } else {
    return fail(
      'unsupported_spec_version',
      `specification for \`${rawId}\` declares neither swagger 2.0 nor openapi 3.x`,
    )
  }
  if (isFailure(servers)) return servers

  const { rules, capped } = permissionRules(doc)
  const specRef = {
    id: rawId,
    url: specUrl,
    format,
    byte_size: byteSize,
    summary: summary?.slice(0, SUMMARY_MAX),
  }
  const description = capped
    ? `${title} from its ${format} specification; read rules capped at ${MAX_PERMISSION_RULES}.`
    : `${title} from its ${format} specification.`

  return {
    specRef,
    profile: {
      profile_id: PROFILE_ID,
      api_id: apiId,
      description: description.slice(0, 500),
      provenance: {
        origins: SOURCE_ID,
        ...(servers.basePath ? { base_path: SOURCE_ID } : {}),
        auth: SOURCE_ID,
        permissions: SOURCE_ID,
        network_scope: SOURCE_ID,
        spec_ref: SOURCE_ID,
      },
      origins: servers.origins,
      base_path: servers.basePath,
      auth: buildAuth(doc, `${apiId}-${PROFILE_ID}`),
      permissions: rules,
      network_scope: 'public',
      spec_ref: specRef,
      verification: { state: 'candidate' },
    },
  }
}

interface Built {
  metadata: MetadataCandidate
  execution?: ExecutionCandidate
  apiId: string
}

function buildEntry(
  rawId: string,
  entry: z.infer<typeof GuruEntry>,
  contentHash: string,
  specs: Map<string, unknown> | undefined,
  limits: SpecLimits,
): Built | Failure {
  const versions = entry.versions ?? {}
  const preferred = entry.preferred ?? ''
  const version: GuruVersion | undefined = preferred === '' ? undefined : versions[preferred]
  if (!version) {
    return fail(
      'no_preferred_version',
      `entry \`${rawId}\` names preferred version \`${preferred || '(absent)'}\`, which it does not declare`,
    )
  }
  const specUrl = asUrl(version.swaggerUrl) ?? asUrl(version.swaggerYamlUrl)
  if (!specUrl) {
    return fail('missing_spec_url', `version \`${preferred}\` of \`${rawId}\` declares no spec url`)
  }

  const info = version.info ?? {}
  const title = asString(info.title) ?? rawId
  const description = asString(info.description) ?? ''
  const categories = Array.isArray(info['x-apisguru-categories'])
    ? info['x-apisguru-categories'].filter((item): item is string => typeof item === 'string')
    : []

  const conforming = CANONICAL_ID_PATTERN.test(rawId)
  const apiId = conforming ? rawId : slugify(rawId)
  if (apiId === '') {
    return fail('schema_mismatch', `entry id \`${rawId}\` slugifies to an empty canonical id`)
  }
  // A raw id outside the canonical form is kept as a source-qualified alias.
  const alias = conforming ? undefined : aliasFor(`${SOURCE_ID}:${rawId}`)

  const spec = specs?.get(rawId)
  const resolved =
    spec === undefined
      ? undefined
      : resolveSpec(rawId, apiId, specUrl, title, description, spec, limits)
  if (resolved && isFailure(resolved)) return resolved

  const record = {
    id: apiId,
    name: title,
    description,
    documentation: asUrl(version.link),
    categories,
    tags: [],
    aliases: alias ? [alias] : [],
    sources: [SOURCE_ID],
    provenance: {
      name: { source: SOURCE_ID, last_observed: title, curated: false },
      description: { source: SOURCE_ID, last_observed: description, curated: false },
      categories: { source: SOURCE_ID, last_observed: categories.join(','), curated: false },
    },
    specs: resolved ? [resolved.specRef] : [],
    profiles: resolved ? [PROFILE_ID] : [],
  }

  return {
    apiId,
    metadata: { record, sourceEntryId: rawId, contentHash },
    execution: resolved
      ? { profile: resolved.profile, sourceEntryId: rawId, contentHash }
      : undefined,
  }
}

export function runApisGuru(
  input: unknown,
  pin: SourcePin,
  specs?: Map<string, unknown>,
  specLimits: SpecLimits = DEFAULT_SPEC_LIMITS,
): AdapterRun {
  const payload = GuruList.safeParse(input)
  if (!payload.success) {
    throw new ApimanacError(
      'validation_failed',
      `source \`${SOURCE_ID}\`: upstream payload is not an api id map — ${describeIssues(payload.error)}`,
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
  const claimed = new Set<string>()

  for (const rawId of Object.keys(payload.data).sort(compare)) {
    const raw = payload.data[rawId]
    const contentHash = entryContentHash(raw)
    const parsed = GuruEntry.safeParse(raw)
    if (!parsed.success) {
      run.rejections.push({
        sourceEntryId: rawId,
        contentHash,
        reasonCode: 'schema_mismatch',
        detail: truncateDetail(describeIssues(parsed.error)),
      })
      continue
    }
    const built = buildEntry(rawId, parsed.data, contentHash, specs, specLimits)
    if (isFailure(built)) {
      run.rejections.push({
        sourceEntryId: rawId,
        contentHash,
        reasonCode: built.reasonCode,
        detail: truncateDetail(built.detail),
      })
      continue
    }
    if (claimed.has(built.apiId)) {
      run.aliased.push({ sourceEntryId: rawId, contentHash, apiId: built.apiId })
      continue
    }
    claimed.add(built.apiId)
    run.metadata.push(built.metadata)
    if (built.execution) run.execution.push(built.execution)
  }

  assertNoVerifiedProfiles(run)
  return run
}

export const apisGuruAdapter: SourceAdapter = {
  sourceId: SOURCE_ID,
  reasons: APIS_GURU_REASONS,
  run: runApisGuru,
}
