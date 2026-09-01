import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { parse } from 'yaml'
import type { ZodTypeAny } from 'zod'
import { ExecutionProfile } from '../schema/execution'
import { RootManifest } from '../schema/manifest'
import { MetadataRecord } from '../schema/metadata'
import { OutcomeLedger, SourceManifest } from '../schema/report'
import { WorkflowDefinition } from '../schema/workflow'
import type { GitContext, PathState } from './git'

/**
 * Deterministic catalog loading. The same schemas parse working-tree files and
 * `HEAD` blobs, so the two projections can never disagree about what a record
 * means — only about which bytes they read.
 */

export const META_DIR = 'catalog/meta'
export const EXECUTION_DIR = 'catalog/execution'
export const SOURCES_DIR = 'catalog/sources'
export const MANIFEST_PATH = 'catalog/manifest.yaml'

export interface LoadedFile<T> {
  readonly file: string
  readonly value: T
  readonly state: PathState
  /**
   * An uncommitted worktree change: untracked, modified, or deleted. A record
   * the snapshot cannot be read at all — no repository, a filtered path, an
   * unreadable blob — is not a draft; `state` carries that.
   */
  readonly draft: boolean
}

export type IssueKind =
  | 'yaml'
  | 'schema'
  | 'filename_mismatch'
  | 'id_collision'
  | 'alias_collision'
  | 'merge_cycle'
  | 'merge_dangling'
  | 'missing_api_reference'
  | 'dangling_profile_link'
  | 'unknown_source'
  | 'tracked_secret'
  | 'evidence_mismatch'
  | 'unsupported_schema_version'
  | 'manifest_missing'
  | 'ledger_mismatch'
  | 'cross_source_composition'
  | 'workflow_orphan'
  | 'invalid_execution_path'
  | 'binding_unpinned'

export interface CatalogIssue {
  readonly kind: IssueKind
  readonly file: string
  readonly field?: string
  readonly message: string
}

/** A workflow definition plus the state of its sibling script file. */
export interface LoadedWorkflow extends LoadedFile<WorkflowDefinition> {
  readonly scriptFile: string
  readonly scriptState: PathState
  readonly scriptDraft: boolean
}

export interface CatalogSnapshot {
  readonly manifest?: RootManifest
  readonly records: Map<string, LoadedFile<MetadataRecord>>
  readonly profiles: Map<string, LoadedFile<ExecutionProfile>>
  readonly workflows: Map<string, LoadedWorkflow>
  readonly sourceManifests: Map<string, LoadedFile<SourceManifest>>
  readonly ledgers: Map<string, LoadedFile<OutcomeLedger>>
  readonly issues: CatalogIssue[]
}

const DRAFT_STATES = new Set<PathState>(['untracked', 'tracked_modified', 'tracked_deleted'])

/** Whether a path state is an uncommitted worktree change. */
export function isDraftState(state: PathState): boolean {
  return DRAFT_STATES.has(state)
}

export function profileKey(apiId: string, profileId: string): string {
  return `${apiId}/${profileId}`
}

export function profilePath(apiId: string, profileId: string): string {
  return `${EXECUTION_DIR}/${apiId}/${profileId}.yaml`
}

export function workflowKey(apiId: string, workflowId: string): string {
  return `${apiId}/${workflowId}`
}

export function workflowPath(apiId: string, workflowId: string): string {
  return `${EXECUTION_DIR}/${apiId}/workflows/${workflowId}.yaml`
}

export function workflowScriptPath(apiId: string, workflowId: string): string {
  return `${EXECUTION_DIR}/${apiId}/workflows/${workflowId}.ts`
}

/**
 * The execution path grammar. Directly under `execution/<api>/`, a yaml is a
 * profile; under `execution/<api>/workflows/`, a yaml+ts pair is a workflow.
 * Anything else below `execution/` is a validation error, never a profile.
 */
const PROFILE_PATH_RE = /^catalog\/execution\/([^/]+)\/([^/]+)\.yaml$/
const WORKFLOW_YAML_RE = /^catalog\/execution\/([^/]+)\/workflows\/([^/]+)\.yaml$/
const WORKFLOW_TS_RE = /^catalog\/execution\/([^/]+)\/workflows\/([^/]+)\.ts$/

export function isProfilePath(file: string): boolean {
  return PROFILE_PATH_RE.test(file)
}

export function isWorkflowDefinitionPath(file: string): boolean {
  return WORKFLOW_YAML_RE.test(file)
}

export function isWorkflowScriptPath(file: string): boolean {
  return WORKFLOW_TS_RE.test(file)
}

export function metadataPath(apiId: string): string {
  return `${META_DIR}/${apiId}.yaml`
}

/** Reads bytes for one catalog-relative path. Absent files yield undefined. */
type ByteReader = (file: string) => Buffer | undefined
/** Lists catalog-relative paths under a directory prefix, sorted. */
type Lister = (prefix: string) => string[]

function parseInto<S extends ZodTypeAny>(
  schema: S,
  file: string,
  bytes: Buffer,
  issues: CatalogIssue[],
): S['_output'] | undefined {
  let document: unknown
  try {
    document = parse(bytes.toString('utf8'))
  } catch (error) {
    issues.push({ kind: 'yaml', file, message: (error as Error).message })
    return undefined
  }
  const result = schema.safeParse(document)
  if (!result.success) {
    for (const issue of result.error.issues) {
      issues.push({
        kind: 'schema',
        file,
        field: issue.path.join('.') || undefined,
        message: issue.message,
      })
    }
    return undefined
  }
  return result.data
}

function loadSnapshot(
  read: ByteReader,
  list: Lister,
  stateOf: (file: string) => PathState,
): CatalogSnapshot {
  const issues: CatalogIssue[] = []
  const records = new Map<string, LoadedFile<MetadataRecord>>()
  const profiles = new Map<string, LoadedFile<ExecutionProfile>>()
  const workflows = new Map<string, LoadedWorkflow>()
  const sourceManifests = new Map<string, LoadedFile<SourceManifest>>()
  const ledgers = new Map<string, LoadedFile<OutcomeLedger>>()

  const manifestBytes = read(MANIFEST_PATH)
  let manifest: RootManifest | undefined
  if (!manifestBytes) {
    issues.push({
      kind: 'manifest_missing',
      file: MANIFEST_PATH,
      message: 'the catalog root manifest is missing',
    })
  } else {
    manifest = parseInto(RootManifest, MANIFEST_PATH, manifestBytes, issues)
  }

  const wrap = <T>(file: string, value: T): LoadedFile<T> => {
    const state = stateOf(file)
    return { file, value, state, draft: isDraftState(state) }
  }

  for (const file of list(META_DIR)) {
    const bytes = read(file)
    if (!bytes) continue
    const record = parseInto(MetadataRecord, file, bytes, issues)
    if (!record) continue
    const expected = metadataPath(record.id)
    if (file !== expected) {
      issues.push({
        kind: 'filename_mismatch',
        file,
        field: 'id',
        message: `declares id \`${record.id}\`, which belongs in ${expected}`,
      })
    }
    const existing = records.get(record.id)
    if (existing) {
      issues.push({
        kind: 'id_collision',
        file,
        field: 'id',
        message: `canonical id \`${record.id}\` is already declared by ${existing.file}`,
      })
      continue
    }
    records.set(record.id, wrap(file, record))
  }

  const executionFiles = list(EXECUTION_DIR)
  const scriptFiles = new Set(executionFiles.filter((file) => isWorkflowScriptPath(file)))
  for (const file of executionFiles) {
    if (isProfilePath(file)) {
      const bytes = read(file)
      if (!bytes) continue
      const profile = parseInto(ExecutionProfile, file, bytes, issues)
      if (!profile) continue
      const expected = profilePath(profile.api_id, profile.profile_id)
      if (file !== expected) {
        issues.push({
          kind: 'filename_mismatch',
          file,
          message: `declares ${profile.api_id}/${profile.profile_id}, which belongs in ${expected}`,
        })
      }
      const key = profileKey(profile.api_id, profile.profile_id)
      const existing = profiles.get(key)
      if (existing) {
        issues.push({
          kind: 'id_collision',
          file,
          message: `profile \`${key}\` is already declared by ${existing.file}`,
        })
        continue
      }
      profiles.set(key, wrap(file, profile))
      continue
    }
    if (isWorkflowDefinitionPath(file)) {
      const bytes = read(file)
      if (!bytes) continue
      const definition = parseInto(WorkflowDefinition, file, bytes, issues)
      if (!definition) continue
      const expected = workflowPath(definition.api_id, definition.workflow_id)
      if (file !== expected) {
        issues.push({
          kind: 'filename_mismatch',
          file,
          message: `declares ${definition.api_id}/${definition.workflow_id}, which belongs in ${expected}`,
        })
      }
      const scriptFile = `${file.slice(0, -'.yaml'.length)}.ts`
      if (!scriptFiles.has(scriptFile) || !read(scriptFile)) {
        issues.push({
          kind: 'workflow_orphan',
          file,
          message: `has no sibling script at ${scriptFile}`,
        })
        continue
      }
      const key = workflowKey(definition.api_id, definition.workflow_id)
      const existing = workflows.get(key)
      if (existing) {
        issues.push({
          kind: 'id_collision',
          file,
          message: `workflow \`${key}\` is already declared by ${existing.file}`,
        })
        continue
      }
      const scriptState = stateOf(scriptFile)
      workflows.set(key, {
        ...wrap(file, definition),
        scriptFile,
        scriptState,
        scriptDraft: isDraftState(scriptState),
      })
      continue
    }
    if (isWorkflowScriptPath(file)) {
      const definitionFile = `${file.slice(0, -'.ts'.length)}.yaml`
      if (!read(definitionFile)) {
        issues.push({
          kind: 'workflow_orphan',
          file,
          message: `has no sibling definition at ${definitionFile}`,
        })
      }
      continue
    }
    issues.push({
      kind: 'invalid_execution_path',
      file,
      message:
        'is not `execution/<api-id>/<profile-id>.yaml` or `execution/<api-id>/workflows/<workflow-id>.{yaml,ts}`',
    })
  }

  for (const file of list(SOURCES_DIR)) {
    const bytes = read(file)
    if (!bytes) continue
    const directory = file.slice(SOURCES_DIR.length + 1).split('/')[0] ?? ''
    if (file.endsWith('/manifest.yaml')) {
      const parsed = parseInto(SourceManifest, file, bytes, issues)
      if (!parsed) continue
      if (parsed.source_id !== directory) {
        issues.push({
          kind: 'filename_mismatch',
          file,
          field: 'source_id',
          message: `declares source \`${parsed.source_id}\` but sits under ${SOURCES_DIR}/${directory}`,
        })
      }
      const existing = sourceManifests.get(parsed.source_id)
      if (existing) {
        issues.push({
          kind: 'id_collision',
          file,
          field: 'source_id',
          message: `source \`${parsed.source_id}\` is already declared by ${existing.file}`,
        })
        continue
      }
      sourceManifests.set(parsed.source_id, wrap(file, parsed))
    } else if (file.endsWith('/outcomes.yaml')) {
      const parsed = parseInto(OutcomeLedger, file, bytes, issues)
      if (!parsed) continue
      if (parsed.source_id !== directory) {
        issues.push({
          kind: 'filename_mismatch',
          file,
          field: 'source_id',
          message: `declares source \`${parsed.source_id}\` but sits under ${SOURCES_DIR}/${directory}`,
        })
      }
      const existing = ledgers.get(parsed.source_id)
      if (existing) {
        issues.push({
          kind: 'id_collision',
          file,
          field: 'source_id',
          message: `source \`${parsed.source_id}\` is already declared by ${existing.file}`,
        })
        continue
      }
      ledgers.set(parsed.source_id, wrap(file, parsed))
    }
  }

  return { manifest, records, profiles, workflows, sourceManifests, ledgers, issues }
}

function walkFiles(
  root: string,
  prefix: string,
  extensions: readonly string[] = ['.yaml'],
): string[] {
  const absolute = join(root, prefix)
  if (!existsSync(absolute)) return []
  const found: string[] = []
  const visit = (relative: string): void => {
    const entries = readdirSync(join(root, relative), { withFileTypes: true })
    // Sorted so a build over the same catalog reads files in the same order.
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0))
    for (const entry of entries) {
      const child = `${relative}/${entry.name}`
      if (entry.isDirectory()) visit(child)
      else if (extensions.some((extension) => entry.name.endsWith(extension))) found.push(child)
    }
  }
  visit(prefix)
  return found
}

/** Catalog files the loaders consider: yaml everywhere, ts only for workflow scripts. */
function isCatalogPath(file: string): boolean {
  if (!file.startsWith('catalog/')) return false
  return file.endsWith('.yaml') || isWorkflowScriptPath(file)
}

/** The working tree: what search, inspection, and validation read. */
export function loadWorkingTree(catalogRoot: string, git: GitContext): CatalogSnapshot {
  const files = new Set<string>([
    MANIFEST_PATH,
    ...walkFiles(catalogRoot, META_DIR),
    ...walkFiles(catalogRoot, EXECUTION_DIR, ['.yaml', '.ts']),
    ...walkFiles(catalogRoot, SOURCES_DIR),
  ])
  // A committed file deleted from the worktree still has to appear, labeled deleted.
  for (const tracked of [...git.trackedPaths(), ...git.committedPaths()]) {
    if (isCatalogPath(tracked)) files.add(tracked)
  }
  const blobs = git.readHeadBlobs([...files])
  const states = new Map<string, PathState>()
  for (const file of files) states.set(file, git.pathState(file, blobs.get(file)))

  return loadSnapshot(
    (file) => {
      const absolute = join(catalogRoot, file)
      return existsSync(absolute) ? readFileSync(absolute) : undefined
    },
    (prefix) => [...files].filter((file) => file.startsWith(`${prefix}/`)).sort(),
    (file) => states.get(file) ?? git.pathState(file),
  )
}

/** The committed snapshot: what execution authority is derived from. */
export function loadCommitted(git: GitContext): CatalogSnapshot {
  if (!git.available) {
    return {
      records: new Map(),
      profiles: new Map(),
      workflows: new Map(),
      sourceManifests: new Map(),
      ledgers: new Map(),
      issues: [
        {
          kind: 'manifest_missing',
          file: MANIFEST_PATH,
          message: git.unavailableReason ?? 'no reviewed snapshot',
        },
      ],
    }
  }
  const tracked = [...git.committedPaths()].filter(isCatalogPath).sort()
  const blobs = git.readHeadBlobs(tracked)
  return loadSnapshot(
    (file) => blobs.get(file)?.bytes,
    (prefix) => tracked.filter((file) => file.startsWith(`${prefix}/`)),
    (file) => git.pathState(file, blobs.get(file)),
  )
}
