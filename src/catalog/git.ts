import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'

/**
 * The committed snapshot, read through `git` plumbing with a fixed argument
 * vector and no shell. Every failure mode returns a reason rather than
 * defaulting to eligible.
 */

export type GitUnavailableReason =
  | 'not_a_repository'
  | 'no_commits'
  | 'unreadable_head'
  | 'git_unavailable'

export interface GitUnavailable {
  readonly available: false
  readonly reason: GitUnavailableReason
  readonly detail: string
}

export interface GitAvailable {
  readonly available: true
  /** Absolute path of the repository worktree root. */
  readonly repositoryRoot: string
  /** Catalog-root-relative paths are prefixed with this to reach repo-relative ones. */
  readonly prefix: string
  readonly head: string
}

export type GitStatus = GitAvailable | GitUnavailable

/** State of one catalog file relative to the committed snapshot. */
export type PathState =
  | 'tracked_clean'
  | 'tracked_modified'
  | 'tracked_deleted'
  | 'untracked'
  | 'filtered'
  | 'unreadable_blob'
  | 'no_snapshot'

export interface BlobResult {
  readonly present: boolean
  readonly bytes?: Buffer
  readonly reason?: string
}

function run(cwd: string, args: string[], input?: Buffer): Buffer {
  return execFileSync('git', args, {
    cwd,
    input,
    maxBuffer: 512 * 1024 * 1024,
    stdio: ['pipe', 'pipe', 'pipe'],
    encoding: 'buffer',
  }) as unknown as Buffer
}

function runText(cwd: string, args: string[]): string {
  return run(cwd, args).toString('utf8')
}

/**
 * A catalog root's Git context. `HEAD` is resolved when this opens, so one
 * context is one snapshot: construct it per command, and per MCP tool
 * invocation, or a long-lived process keeps comparing against the commit it
 * launched on.
 */
export class GitContext {
  private trackedCache: Set<string> | undefined
  private committedCache: Set<string> | undefined
  private filteredCache: Map<string, boolean> = new Map()

  private constructor(
    readonly catalogRoot: string,
    readonly status: GitStatus,
  ) {}

  static open(catalogRoot: string): GitContext {
    let repositoryRoot: string
    let prefix: string
    try {
      repositoryRoot = runText(catalogRoot, ['rev-parse', '--show-toplevel']).trim()
      prefix = runText(catalogRoot, ['rev-parse', '--show-prefix']).trim()
    } catch (error) {
      const detail = describe(error)
      if (/not a git repository/i.test(detail)) {
        return new GitContext(catalogRoot, {
          available: false,
          reason: 'not_a_repository',
          detail: `${catalogRoot} is not inside a Git repository`,
        })
      }
      return new GitContext(catalogRoot, {
        available: false,
        reason: 'git_unavailable',
        detail,
      })
    }
    let head: string
    try {
      head = runText(catalogRoot, ['rev-parse', '--verify', 'HEAD^{commit}']).trim()
    } catch (error) {
      const detail = describe(error)
      // An unborn HEAD is a repository with no commits; anything else is unreadable.
      let hasCommits = true
      try {
        hasCommits = runText(catalogRoot, ['rev-list', '--all', '--max-count=1']).trim().length > 0
      } catch {
        hasCommits = true
      }
      const reason: GitUnavailableReason = hasCommits ? 'unreadable_head' : 'no_commits'
      return new GitContext(catalogRoot, {
        available: false,
        reason,
        detail:
          reason === 'no_commits'
            ? `${repositoryRoot} has no commits, so there is no reviewed snapshot`
            : `HEAD in ${repositoryRoot} could not be read: ${detail}`,
      })
    }
    return new GitContext(catalogRoot, { available: true, repositoryRoot, prefix, head })
  }

  get available(): boolean {
    return this.status.available
  }

  /** Why the committed snapshot is unavailable, or undefined when it is. */
  get unavailableReason(): string | undefined {
    return this.status.available ? undefined : this.status.detail
  }

  get head(): string | undefined {
    return this.status.available ? this.status.head : undefined
  }

  private repoPath(catalogRelative: string): string {
    const prefix = this.status.available ? this.status.prefix : ''
    return `${prefix}${catalogRelative}`
  }

  /** Catalog-root-relative paths the index tracks. */
  trackedPaths(): Set<string> {
    if (this.trackedCache) return this.trackedCache
    const tracked = new Set<string>()
    if (!this.status.available) {
      this.trackedCache = tracked
      return tracked
    }
    const prefix = this.status.prefix
    const output = run(this.catalogRoot, ['ls-files', '-z', '--full-name']).toString('utf8')
    for (const entry of output.split('\0')) {
      if (!entry) continue
      if (prefix && !entry.startsWith(prefix)) continue
      tracked.add(prefix ? entry.slice(prefix.length) : entry)
    }
    this.trackedCache = tracked
    return tracked
  }

  /**
   * Catalog-root-relative paths present in the `HEAD` tree. This is not the
   * index: `git rm --cached` removes a path from the index while it remains
   * committed, and execution authority follows the commit.
   */
  committedPaths(): Set<string> {
    if (this.committedCache) return this.committedCache
    const committed = new Set<string>()
    if (!this.status.available) {
      this.committedCache = committed
      return committed
    }
    const prefix = this.status.prefix
    let output: string
    try {
      output = run(this.catalogRoot, [
        'ls-tree',
        '-r',
        '-z',
        '--name-only',
        '--full-tree',
        this.status.head,
      ]).toString('utf8')
    } catch {
      // An unreadable tree yields no committed paths, so nothing is eligible.
      this.committedCache = committed
      return committed
    }
    for (const entry of output.split('\0')) {
      if (!entry) continue
      if (prefix && !entry.startsWith(prefix)) continue
      committed.add(prefix ? entry.slice(prefix.length) : entry)
    }
    this.committedCache = committed
    return committed
  }

  /**
   * A path whose bytes a clean/smudge or eol filter would rewrite cannot be
   * byte-compared against its blob, so it is treated as ineligible.
   */
  isFiltered(catalogRelative: string): boolean {
    const cached = this.filteredCache.get(catalogRelative)
    if (cached !== undefined) return cached
    let filtered = false
    try {
      const output = run(this.catalogRoot, [
        'check-attr',
        '-z',
        'text',
        'eol',
        'filter',
        '--',
        this.repoPath(catalogRelative),
      ]).toString('utf8')
      const fields = output.split('\0')
      for (let i = 0; i + 2 < fields.length; i += 3) {
        const attribute = fields[i + 1]
        const value = fields[i + 2]
        if (value === 'unspecified' || value === 'unset') continue
        if (attribute === 'text') filtered = true
        if (attribute === 'eol') filtered = true
        if (attribute === 'filter') filtered = true
      }
    } catch {
      // A check-attr failure is not evidence that no filter applies.
      filtered = true
    }
    this.filteredCache.set(catalogRelative, filtered)
    return filtered
  }

  /** Batched `HEAD` blob reads: one `cat-file --batch` process for all paths. */
  readHeadBlobs(catalogRelativePaths: readonly string[]): Map<string, BlobResult> {
    const results = new Map<string, BlobResult>()
    if (!this.status.available) {
      for (const path of catalogRelativePaths) {
        results.set(path, { present: false, reason: this.status.detail })
      }
      return results
    }
    if (catalogRelativePaths.length === 0) return results
    const head = this.status.head
    const specs = catalogRelativePaths.map((path) => `${head}:${this.repoPath(path)}`)
    let output: Buffer
    try {
      output = run(this.catalogRoot, ['cat-file', '--batch'], Buffer.from(`${specs.join('\n')}\n`))
    } catch (error) {
      const detail = describe(error)
      for (const path of catalogRelativePaths) {
        results.set(path, { present: false, reason: `blob read failed: ${detail}` })
      }
      return results
    }
    let offset = 0
    for (const path of catalogRelativePaths) {
      const newline = output.indexOf(0x0a, offset)
      if (newline === -1) {
        results.set(path, { present: false, reason: 'truncated cat-file output' })
        continue
      }
      const header = output.subarray(offset, newline).toString('utf8')
      offset = newline + 1
      const parts = header.split(' ')
      const last = parts.at(-1)
      if (last === 'missing' || last === 'ambiguous') {
        results.set(path, { present: false, reason: `not present in HEAD (${last})` })
        continue
      }
      const size = Number(parts.at(-1))
      if (!Number.isFinite(size)) {
        results.set(path, { present: false, reason: `unreadable cat-file header: ${header}` })
        continue
      }
      results.set(path, { present: true, bytes: output.subarray(offset, offset + size) })
      offset += size + 1
    }
    return results
  }

  readHeadBlob(catalogRelative: string): BlobResult {
    return (
      this.readHeadBlobs([catalogRelative]).get(catalogRelative) ?? {
        present: false,
        reason: 'no result',
      }
    )
  }

  private worktreeBytes(catalogRelative: string): Buffer | undefined {
    try {
      return readFileSync(join(this.catalogRoot, catalogRelative))
    } catch {
      return undefined
    }
  }

  /** Byte-for-byte comparison of one worktree file against its `HEAD` blob. */
  pathState(catalogRelative: string, blob?: BlobResult): PathState {
    if (!this.status.available) return 'no_snapshot'
    if (this.isFiltered(catalogRelative)) return 'filtered'
    const tracked = this.committedPaths().has(catalogRelative)
    const worktree = this.worktreeBytes(catalogRelative)
    const committed = blob ?? this.readHeadBlob(catalogRelative)
    if (!tracked && !committed.present) return 'untracked'
    if (!committed.present) {
      return committed.reason?.startsWith('not present in HEAD') ? 'untracked' : 'unreadable_blob'
    }
    if (!worktree) return 'tracked_deleted'
    return committed.bytes && worktree.equals(committed.bytes)
      ? 'tracked_clean'
      : 'tracked_modified'
  }
}

function describe(error: unknown): string {
  const stderr = (error as { stderr?: Buffer | string }).stderr
  if (stderr)
    return Buffer.isBuffer(stderr) ? stderr.toString('utf8').trim() : String(stderr).trim()
  return error instanceof Error ? error.message : String(error)
}

/** Human sentence for a path state, used in refusal reasons. */
export function describePathState(state: PathState, file: string): string {
  switch (state) {
    case 'tracked_clean':
      return `${file} matches the committed snapshot`
    case 'tracked_modified':
      return `${file} differs from the committed snapshot`
    case 'tracked_deleted':
      return `${file} is committed but deleted from the worktree`
    case 'untracked':
      return `${file} has never been committed`
    case 'filtered':
      return `${file} passes through a Git content filter, so its bytes cannot be compared to the committed blob`
    case 'unreadable_blob':
      return `${file} is tracked but its committed blob could not be read`
    case 'no_snapshot':
      return `${file} has no reviewed snapshot to compare against`
  }
}
