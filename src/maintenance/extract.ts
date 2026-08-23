import { parse } from 'yaml'
export { slugify } from '../schema/vocab'

/**
 * Local extraction. `add` tries, in order: parse the fetched document as an
 * OpenAPI specification, then extract metadata locally from it, and only then
 * an external extractor.
 */

export type ExtractionMethod = 'openapi' | 'local' | 'external' | 'manual'

export interface Extraction {
  readonly method: ExtractionMethod
  readonly name: string
  readonly description: string
  readonly documentation?: string
  readonly categories: string[]
  readonly tags: string[]
  /** Exact origins the specification declares. Absent for non-specification input. */
  readonly origins: string[]
  readonly basePath?: string
  readonly specFormat?: 'openapi-3' | 'swagger-2'
  readonly specByteSize?: number
  readonly operations: { method: string; path: string }[]
}

interface OpenApiDocument {
  openapi?: string
  swagger?: string
  info?: { title?: string; description?: string; version?: string }
  servers?: { url?: string }[]
  host?: string
  basePath?: string
  schemes?: string[]
  paths?: Record<string, Record<string, unknown>>
  tags?: { name?: string }[]
}

function parseDocument(bytes: Buffer): OpenApiDocument | undefined {
  const text = bytes.toString('utf8')
  try {
    return JSON.parse(text) as OpenApiDocument
  } catch {
    try {
      const parsed = parse(text) as unknown
      return parsed && typeof parsed === 'object' ? (parsed as OpenApiDocument) : undefined
    } catch {
      return undefined
    }
  }
}

function serverOrigins(document: OpenApiDocument): { origins: string[]; basePath?: string } {
  if (document.openapi?.startsWith('3')) {
    const origins: string[] = []
    let basePath: string | undefined
    for (const server of document.servers ?? []) {
      if (!server.url) continue
      try {
        const url = new URL(server.url)
        origins.push(url.origin)
        if (url.pathname && url.pathname !== '/') basePath ??= url.pathname.replace(/\/$/, '')
      } catch {
        // A server template such as `{scheme}://{host}` yields no origin.
      }
    }
    return { origins: [...new Set(origins)], basePath }
  }
  if (document.swagger === '2.0' && document.host) {
    const schemes = document.schemes?.length ? document.schemes : ['https']
    const origins = schemes
      .filter((scheme) => scheme === 'https' || scheme === 'http')
      .map((scheme) => `${scheme}://${document.host}`)
    return {
      origins,
      basePath: document.basePath && document.basePath !== '/' ? document.basePath : undefined,
    }
  }
  return { origins: [] }
}

const READ_METHODS = new Set(['get', 'head'])

/** Parse the fetched document as an OpenAPI specification. */
export function extractOpenApi(bytes: Buffer, url: string): Extraction | undefined {
  const document = parseDocument(bytes)
  if (!document) return undefined
  const isOpenApi3 = typeof document.openapi === 'string' && document.openapi.startsWith('3')
  const isSwagger2 = document.swagger === '2.0'
  if (!isOpenApi3 && !isSwagger2) return undefined
  const title = document.info?.title
  if (!title) return undefined

  const { origins, basePath } = serverOrigins(document)
  const operations: { method: string; path: string }[] = []
  for (const [path, item] of Object.entries(document.paths ?? {})) {
    for (const method of Object.keys(item ?? {})) {
      if (!READ_METHODS.has(method.toLowerCase())) continue
      operations.push({ method: method.toUpperCase(), path: templateToPattern(path) })
    }
  }

  return {
    method: 'openapi',
    name: title,
    description: document.info?.description?.slice(0, 2000) ?? '',
    documentation: url,
    categories: [],
    tags: (document.tags ?? [])
      .map((tag) => tag.name)
      .filter((name): name is string => Boolean(name)),
    origins,
    basePath,
    specFormat: isOpenApi3 ? 'openapi-3' : 'swagger-2',
    specByteSize: bytes.byteLength,
    operations,
  }
}

/** `{id}` path templates become single-segment wildcards. */
export function templateToPattern(path: string): string {
  const normalized = path.startsWith('/') ? path : `/${path}`
  return normalized.replace(/\{[^}/]+\}/g, '*')
}

const TITLE = /<title[^>]*>([\s\S]{1,300}?)<\/title>/i
const DESCRIPTION = /<meta[^>]+name=["']description["'][^>]+content=["']([\s\S]{1,600}?)["']/i
const OG_DESCRIPTION =
  /<meta[^>]+property=["']og:description["'][^>]+content=["']([\s\S]{1,600}?)["']/i

/** Extract metadata locally from a fetched document that is not a specification. */
export function extractLocal(bytes: Buffer, url: string): Extraction | undefined {
  const text = bytes.toString('utf8')
  const title = TITLE.exec(text)?.[1]?.trim()
  if (!title) return undefined
  const description = (DESCRIPTION.exec(text)?.[1] ?? OG_DESCRIPTION.exec(text)?.[1] ?? '').trim()
  return {
    method: 'local',
    name: title.replace(/\s+/g, ' '),
    description,
    documentation: url,
    categories: [],
    tags: [],
    // A documentation link never yields an execution origin.
    origins: [],
    operations: [],
  }
}
