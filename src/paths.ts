import { homedir } from 'node:os'
import { join } from 'node:path'

/**
 * XDG roots, resolved once per process. Every APImanac path is anchored here,
 * so launching from an arbitrary project directory never writes into it.
 */

export interface XdgRoots {
  readonly config: string
  readonly data: string
  readonly cache: string
  readonly state: string
}

function resolveRoots(): XdgRoots {
  const home = homedir()
  const pick = (variable: string, fallback: string): string => {
    const value = process.env[variable]
    return value?.startsWith('/') ? value : fallback
  }
  return {
    config: join(pick('XDG_CONFIG_HOME', join(home, '.config')), 'apimanac'),
    data: join(pick('XDG_DATA_HOME', join(home, '.local', 'share')), 'apimanac'),
    cache: join(pick('XDG_CACHE_HOME', join(home, '.cache')), 'apimanac'),
    state: join(pick('XDG_STATE_HOME', join(home, '.local', 'state')), 'apimanac'),
  }
}

let roots: XdgRoots | undefined

/** The roots for this process. Resolved on first use and never re-read. */
export function xdg(): XdgRoots {
  if (!roots) roots = resolveRoots()
  return roots
}

/** Test-only: drop the memoized roots so a new environment takes effect. */
export function resetXdgForTests(): void {
  roots = undefined
}

export const paths = {
  configFile: () => join(xdg().config, 'config.yaml'),
  grantsFile: () => join(xdg().config, 'grants.yaml'),
  credentialsDir: () => join(xdg().data, 'credentials'),
  downloadsDir: () => join(xdg().data, 'downloads'),
  catalogDb: () => join(xdg().cache, 'catalog.db'),
  responseCacheDir: () => join(xdg().cache, 'responses'),
  responseCacheDb: () => join(xdg().cache, 'responses', 'index.db'),
  responseCacheKey: () => join(xdg().cache, 'responses', 'cache.key'),
  healthDb: () => join(xdg().state, 'health.db'),
}
