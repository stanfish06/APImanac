import { Database } from 'bun:sqlite'
import { existsSync } from 'node:fs'
import type { CatalogRoot } from '../catalog/root'
import { paths } from '../paths'
import { BUILDER_VERSION, readMeta } from './schema'
import { BUILDER_KEY, HEAD_KEY, INPUT_HASH_KEY, buildStore, canonicalInputHash } from './build'

/**
 * Store access with automatic rebuild. Staleness is a property of the recorded
 * input hash, which covers both worktree bytes and the resolved `HEAD`, so a
 * commit that leaves the worktree byte-identical still triggers a rebuild.
 */

export interface OpenOptions {
  readonly storePath?: string
  /** Refuse to build; used by read paths that must not write. */
  readonly noRebuild?: boolean
}

export interface OpenedStore {
  readonly db: Database
  readonly path: string
  readonly rebuilt: boolean
  close(): void
}

export function storePathFor(options: OpenOptions = {}): string {
  return options.storePath ?? paths.catalogDb()
}

export function isStale(root: CatalogRoot, storePath: string): boolean {
  if (!existsSync(storePath)) return true
  let db: Database
  try {
    db = new Database(storePath, { readonly: true })
  } catch {
    return true
  }
  try {
    if (readMeta(db, BUILDER_KEY) !== BUILDER_VERSION) return true
    if (readMeta(db, HEAD_KEY) !== (root.git.head ?? '')) return true
    return readMeta(db, INPUT_HASH_KEY) !== canonicalInputHash(root)
  } catch {
    return true
  } finally {
    db.close()
  }
}

export function openStore(root: CatalogRoot, options: OpenOptions = {}): OpenedStore {
  const path = storePathFor(options)
  let rebuilt = false
  if (isStale(root, path)) {
    if (options.noRebuild) {
      throw new Error(`the derived store at ${path} is stale and rebuilding was not permitted`)
    }
    buildStore(root, { storePath: path })
    rebuilt = true
  }
  const db = new Database(path, { readonly: true })
  return { db, path, rebuilt, close: () => db.close() }
}
