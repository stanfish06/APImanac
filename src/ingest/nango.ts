import { z } from 'zod'
import { ApimanacError } from '../errors'
import { BasePath, Origin } from '../schema/execution'
import { NANGO_REASONS } from '../schema/reasons'
import { COMPONENT_NAME_PATTERN } from '../schema/vocab'
import {
  type AdapterRun,
  aliasFor,
  assertNoVerifiedProfiles,
  compare,
  describeIssues,
  entryContentHash,
  type MetadataCandidate,
  type SourceAdapter,
  type SourcePin,
  slugify,
  truncateDetail,
} from './adapter'

/**
 * Nango's `providers.yaml` describes how its proxy calls each provider. The
 * adapter keeps those semantics rather than flattening them: aliases expand
 * against their target, every proxy header and query value stays a separately
 * named credential component, and a construct the wire template cannot express
 * rejects the whole provider instead of writing half of one.
 */

const SOURCE_ID = 'nango'
const PROFILE_ID = 'nango'

const NangoProxy = z
  .object({
    base_url: z.string().optional(),
    headers: z.record(z.string(), z.string()).optional(),
    query: z.record(z.string(), z.string()).optional(),
    retry: z.unknown().optional(),
    verification: z.unknown().optional(),
  })
  .passthrough()

const NangoProvider = z
  .object({
    display_name: z.string().optional(),
    alias: z.string().optional(),
    auth_mode: z.string().optional(),
    base_url: z.string().optional(),
    docs: z.string().optional(),
    categories: z.array(z.string()).optional(),
    proxy: NangoProxy.optional(),
    connection_config: z.record(z.string(), z.unknown()).optional(),
    credentials: z.record(z.string(), z.unknown()).optional(),
  })
  .passthrough()

const NangoProviders = z.record(z.string(), z.unknown())

const NangoScopes = z.record(
  z.string(),
  z.union([
    z.array(z.string()),
    z.object({ scopes: z.array(z.string()).optional() }).passthrough(),
  ]),
)

type NangoProvider = z.infer<typeof NangoProvider>

/** Auth modes v0 can execute; every other mode is rejected rather than approximated. */
const SUPPORTED_AUTH_MODES: Record<string, 'bearer' | 'basic' | 'api_key'> = {
  BEARER: 'bearer',
  APP: 'bearer',
  BASIC: 'basic',
  API_KEY: 'api_key',
}

interface Failure {
  reasonCode: string
  detail: string
}

function fail(reasonCode: string, detail: string): Failure {
  return { reasonCode, detail }
}

function isFailure(value: unknown): value is Failure {
  return typeof value === 'object' && value !== null && 'reasonCode' in value
}

const TEMPLATE_SCAN = /\$\{([^}]*)\}/g
const PLAIN_PLACEHOLDER = /^[A-Za-z_][A-Za-z0-9_]*$/

function snakeCase(name: string): string | undefined {
  const value = name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '_')
    .replace(/^_+|_+$/g, '')
  return COMPONENT_NAME_PATTERN.test(value) ? value : undefined
}

interface Converted {
  template: string
  names: string[]
}

/** `${name}` becomes `{snake_name}`; anything richer is refused, never approximated. */
function convertTemplate(raw: string): Converted | Failure {
  const literal = raw.replace(TEMPLATE_SCAN, '')
  if (literal.includes('{') || literal.includes('}')) {
    return fail('unsupported_template_construct', `template \`${raw}\` contains a literal brace`)
  }
  const names: string[] = []
  let broke: Failure | undefined
  const template = raw.replace(TEMPLATE_SCAN, (_match, inner: string) => {
    if (inner.includes('.')) {
      broke ??= fail(
        'connection_configuration_required',
        `template \`${raw}\` reads \`${inner}\` from per-connection configuration`,
      )
      return ''
    }
    if (!PLAIN_PLACEHOLDER.test(inner)) {
      broke ??= fail(
        'unsupported_template_construct',
        `template \`${raw}\` uses the construct \`${inner}\`, which is not a plain placeholder`,
      )
      return ''
    }
    const name = snakeCase(inner)
    if (!name) {
      broke ??= fail(
        'unsupported_template_construct',
        `template \`${raw}\` placeholder \`${inner}\` has no component name`,
      )
      return ''
    }
    names.push(name)
    return `{${name}}`
  })
  return broke ?? { template, names }
}

interface Placed {
  kind: 'header' | 'query'
  field: string
  template: string
  names: string[]
}

/** Headers first, then query, each in sorted key order, so component naming is stable. */
function placements(provider: NangoProvider): Placed[] | Failure {
  const out: Placed[] = []
  const groups: [Placed['kind'], Record<string, string> | undefined][] = [
    ['header', provider.proxy?.headers],
    ['query', provider.proxy?.query],
  ]
  for (const [kind, group] of groups) {
    for (const field of Object.keys(group ?? {}).sort(compare)) {
      const raw = group?.[field]
      if (raw === undefined) continue
      const converted = convertTemplate(raw)
      if (isFailure(converted)) return converted
      if (converted.names.length === 0) continue
      out.push({ kind, field, template: converted.template, names: converted.names })
    }
  }
  return out
}

interface ParsedBaseUrl {
  origin: string
  basePath?: string
}

function parseBaseUrl(raw: string): ParsedBaseUrl | Failure {
  if (raw.includes('${')) {
    return fail(
      'connection_configuration_required',
      `base url \`${raw}\` is templated from per-connection configuration`,
    )
  }
  let parsed: URL
  try {
    parsed = new URL(raw)
  } catch {
    return fail('invalid_base_url', `base url \`${raw}\` is not a parseable absolute URL`)
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') {
    return fail('invalid_base_url', `base url \`${raw}\` does not use http or https`)
  }
  if (parsed.search || parsed.hash) {
    return fail('invalid_base_url', `base url \`${raw}\` carries a query or fragment`)
  }
  const origin = `${parsed.protocol}//${parsed.host}`.toLowerCase()
  if (!Origin.safeParse(origin).success) {
    return fail('invalid_base_url', `base url \`${raw}\` does not reduce to an exact origin`)
  }
  const path = parsed.pathname.replace(/\/+$/, '')
  if (path === '') return { origin }
  if (!BasePath.safeParse(path).success) {
    return fail('invalid_base_url', `base url \`${raw}\` has an unusable base path \`${path}\``)
  }
  return { origin, basePath: path }
}

function scopesFor(scopes: z.infer<typeof NangoScopes> | undefined, key: string): string[] {
  const entry = scopes?.[key]
  if (!entry) return []
  return Array.isArray(entry) ? [...entry] : [...(entry.scopes ?? [])]
}

function documentationUrl(raw: string | undefined): string | undefined {
  if (!raw) return undefined
  try {
    const parsed = new URL(raw)
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:') return undefined
    return parsed.toString()
  } catch {
    return undefined
  }
}

interface Built {
  metadata: MetadataCandidate
  execution: { profile: unknown; sourceEntryId: string; contentHash: string }
}

function buildProvider(
  key: string,
  provider: NangoProvider,
  contentHash: string,
  scopes: string[],
): Built | Failure {
  const displayName = provider.display_name?.trim() ?? ''
  if (displayName === '')
    return fail('missing_display_name', `provider \`${key}\` has no display_name`)

  const mode = provider.auth_mode ?? ''
  const family = SUPPORTED_AUTH_MODES[mode]
  if (!family) {
    return fail(
      'unsupported_auth_mode',
      `provider \`${key}\` declares auth_mode \`${mode || '(absent)'}\`, which v0 cannot execute`,
    )
  }

  const rawBaseUrl = provider.proxy?.base_url ?? provider.base_url
  if (!rawBaseUrl || rawBaseUrl.trim() === '') {
    return fail('missing_base_url', `provider \`${key}\` declares no proxy.base_url or base_url`)
  }
  const base = parseBaseUrl(rawBaseUrl.trim())
  if (isFailure(base)) return base

  const placed = placements(provider)
  if (isFailure(placed)) return placed

  const auth = buildAuth(key, family, placed, `${slugify(key)}-${PROFILE_ID}`, scopes)
  if (isFailure(auth)) return auth

  const id = slugify(key)
  const alias = aliasFor(key)
  const documentation = documentationUrl(provider.docs)
  const record = {
    id,
    name: displayName,
    description: '',
    documentation,
    categories: provider.categories ?? [],
    tags: [`auth:${mode.toLowerCase()}`],
    aliases: alias && alias !== id ? [alias] : [],
    sources: [SOURCE_ID],
    provenance: {
      name: { source: SOURCE_ID, last_observed: displayName, curated: false },
      documentation: { source: SOURCE_ID, last_observed: provider.docs ?? '', curated: false },
      categories: {
        source: SOURCE_ID,
        last_observed: (provider.categories ?? []).join(','),
        curated: false,
      },
      tags: { source: SOURCE_ID, last_observed: `auth:${mode.toLowerCase()}`, curated: false },
    },
    profiles: [PROFILE_ID],
  }

  const profile = {
    profile_id: PROFILE_ID,
    api_id: id,
    description: `${displayName} through the Nango proxy base url.`,
    provenance: {
      origins: SOURCE_ID,
      ...(base.basePath ? { base_path: SOURCE_ID } : {}),
      auth: SOURCE_ID,
      network_scope: SOURCE_ID,
    },
    origins: [base.origin],
    base_path: base.basePath,
    auth,
    network_scope: 'public',
    verification: { state: 'candidate' },
  }

  return {
    metadata: { record, sourceEntryId: key, contentHash },
    execution: { profile, sourceEntryId: key, contentHash },
  }
}

interface BuiltAuth {
  type: string
  credential_id: string
  components: { name: string; description?: string }[]
  placements: unknown[]
  scopes: string[]
}

/**
 * The component the auth type requires keeps its required name; every other
 * proxy placeholder stays a component of its own with its own placement.
 */
function buildAuth(
  key: string,
  family: 'bearer' | 'basic' | 'api_key',
  placed: Placed[],
  credentialId: string,
  scopes: string[],
): BuiltAuth | Failure {
  if (family === 'basic') {
    const extras = placed.flatMap((item) => item.names)
    return {
      type: 'basic',
      credential_id: credentialId,
      components: componentList(['username', 'password', ...extras]),
      placements: [
        { kind: 'basic', header: 'Authorization', username: 'username', password: 'password' },
        ...placed.map(toPlacement),
      ],
      scopes,
    }
  }

  const primary = pickPrimary(placed)
  if (!primary) {
    if (family === 'bearer') {
      return {
        type: 'bearer',
        credential_id: credentialId,
        components: componentList(['token']),
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
        scopes,
      }
    }
    return fail(
      'unsupported_auth_mode',
      `provider \`${key}\` declares API_KEY with no proxy header or query template to place the key in`,
    )
  }

  const bearerHeader =
    primary.item.kind === 'header' &&
    primary.item.field.toLowerCase() === 'authorization' &&
    primary.item.template.startsWith('Bearer ')
  const type =
    family === 'bearer' || bearerHeader
      ? 'bearer'
      : primary.item.kind === 'header'
        ? 'header_key'
        : 'query_key'
  const required = type === 'bearer' ? 'token' : 'key'

  const names = placed.flatMap((item) => item.names)
  const renamed = names.includes(required) ? placed : rename(placed, primary.name, required)
  const ordered = [required, ...renamed.flatMap((item) => item.names)]
  return {
    type,
    credential_id: credentialId,
    components: componentList(ordered),
    placements: renamed.map(toPlacement),
    scopes,
  }
}

/** The credential the auth type requires, chosen by name so ordering never picks a bystander. */
const CREDENTIAL_HINT = /(^|_)(api_key|apikey|key|token|secret|password)$/

function pickPrimary(placed: Placed[]): { item: Placed; name: string } | undefined {
  for (const item of placed) {
    const hinted = item.names.find((name) => CREDENTIAL_HINT.test(name))
    if (hinted) return { item, name: hinted }
  }
  const first = placed[0]
  const name = first?.names[0]
  return first && name ? { item: first, name } : undefined
}

function rename(placed: Placed[], from: string, to: string): Placed[] {
  return placed.map((item) => ({
    ...item,
    template: item.template.replaceAll(`{${from}}`, `{${to}}`),
    names: item.names.map((name) => (name === from ? to : name)),
  }))
}

function componentList(names: string[]): { name: string }[] {
  const seen = new Set<string>()
  const out: { name: string }[] = []
  for (const name of names) {
    if (seen.has(name)) continue
    seen.add(name)
    out.push({ name })
  }
  return out
}

function toPlacement(item: Placed): unknown {
  return item.kind === 'header'
    ? { kind: 'header', header: item.field, template: item.template }
    : { kind: 'query', parameter: item.field, template: item.template }
}

export function runNango(input: unknown, pin: SourcePin, scopesInput?: unknown): AdapterRun {
  const payload = NangoProviders.safeParse(input)
  if (!payload.success) {
    throw new ApimanacError(
      'validation_failed',
      `source \`${SOURCE_ID}\`: upstream payload is not a provider key map — ${describeIssues(payload.error)}`,
      { source: SOURCE_ID, shape: describeIssues(payload.error) },
    )
  }
  const scopes = scopesInput === undefined ? undefined : NangoScopes.safeParse(scopesInput)
  if (scopes && !scopes.success) {
    throw new ApimanacError(
      'validation_failed',
      `source \`${SOURCE_ID}\`: scopes file is not a provider key map — ${describeIssues(scopes.error)}`,
      { source: SOURCE_ID, shape: describeIssues(scopes.error) },
    )
  }
  const scopeMap = scopes?.success ? scopes.data : undefined

  const run: AdapterRun = {
    sourceId: SOURCE_ID,
    pin,
    metadata: [],
    execution: [],
    aliased: [],
    rejections: [],
  }
  const providers = new Map<string, { value: NangoProvider; contentHash: string }>()
  for (const key of Object.keys(payload.data).sort(compare)) {
    const raw = payload.data[key]
    const contentHash = entryContentHash(raw)
    const parsed = NangoProvider.safeParse(raw)
    if (!parsed.success) {
      run.rejections.push({
        sourceEntryId: key,
        contentHash,
        reasonCode: 'schema_mismatch',
        detail: truncateDetail(describeIssues(parsed.error)),
      })
      continue
    }
    providers.set(key, { value: parsed.data, contentHash })
  }

  const outcomes = new Map<string, string | Failure>()
  const records = new Map<string, { aliases: string[] }>()
  for (const [key, entry] of providers) {
    if (entry.value.alias) continue
    const built = buildProvider(key, entry.value, entry.contentHash, scopesFor(scopeMap, key))
    if (isFailure(built)) {
      outcomes.set(key, built)
      run.rejections.push({
        sourceEntryId: key,
        contentHash: entry.contentHash,
        reasonCode: built.reasonCode,
        detail: truncateDetail(built.detail),
      })
      continue
    }
    outcomes.set(key, (built.metadata.record as { id: string }).id)
    records.set(key, built.metadata.record as { aliases: string[] })
    run.metadata.push(built.metadata)
    run.execution.push(built.execution)
  }

  for (const [key, entry] of providers) {
    const target = entry.value.alias
    if (!target) continue
    const reject = (reasonCode: string, detail: string) => {
      run.rejections.push({
        sourceEntryId: key,
        contentHash: entry.contentHash,
        reasonCode,
        detail: truncateDetail(detail),
      })
    }
    const resolved = providers.get(target)
    if (!resolved) {
      reject('schema_mismatch', `provider \`${key}\` aliases \`${target}\`, which is not declared`)
      continue
    }
    if (resolved.value.alias) {
      reject(
        'schema_mismatch',
        `provider \`${key}\` aliases \`${target}\`, which is itself an alias`,
      )
      continue
    }
    const outcome = outcomes.get(target)
    if (outcome === undefined || isFailure(outcome)) {
      const detail = outcome
        ? `alias target \`${target}\` was rejected: ${outcome.detail}`
        : `alias target \`${target}\` produced no outcome`
      reject(outcome ? outcome.reasonCode : 'schema_mismatch', detail)
      continue
    }
    const alias = aliasFor(key)
    const record = records.get(target)
    if (record && alias && alias !== outcome && !record.aliases.includes(alias)) {
      record.aliases.push(alias)
    }
    run.aliased.push({ sourceEntryId: key, contentHash: entry.contentHash, apiId: outcome })
  }

  assertNoVerifiedProfiles(run)
  return run
}

export const nangoAdapter: SourceAdapter = {
  sourceId: SOURCE_ID,
  reasons: NANGO_REASONS,
  run: runNango,
}
