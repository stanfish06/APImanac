import { existsSync, readFileSync, statSync } from 'node:fs'
import { isAbsolute, join, resolve } from 'node:path'
import { parse } from 'yaml'
import { paths } from '../paths'
import { GitContext } from './git'

/**
 * The catalog root is configured, never discovered. Precedence is `--catalog`,
 * then `APIMANAC_CATALOG`, then `catalog_root` in the XDG config file. There is
 * no walk-up from the working directory and no default.
 */

export const ROOT_PRECEDENCE =
  '--catalog <path>, then the APIMANAC_CATALOG environment value, then `catalog_root` in $XDG_CONFIG_HOME/apimanac/config.yaml'

export type RootSource = 'argument' | 'environment' | 'config'

export type RootFailureCode =
  | 'not_configured'
  | 'not_a_directory'
  | 'manifest_missing'
  | 'config_unreadable'

export interface RootFailure {
  readonly ok: false
  readonly code: RootFailureCode
  readonly message: string
  readonly path?: string
}

export interface CatalogRoot {
  readonly ok: true
  readonly path: string
  readonly source: RootSource
  readonly manifestPath: string
  readonly git: GitContext
  /**
   * Set when the root resolves but has no reviewed snapshot. Discovery and
   * validation still work; every execution profile is ineligible with this
   * reason.
   */
  readonly noSnapshotReason?: string
}

export type RootResolution = CatalogRoot | RootFailure

interface ConfigRoot {
  readonly path?: string
  /** Set when the file exists but could not be read as configuration. */
  readonly error?: string
}

function readConfigRoot(): ConfigRoot {
  const file = paths.configFile()
  if (!existsSync(file)) return {}
  let document: { catalog_root?: unknown } | null
  try {
    document = parse(readFileSync(file, 'utf8')) as { catalog_root?: unknown } | null
  } catch (error) {
    // A configured-but-broken file is a distinct failure from having configured
    // nothing at all.
    return { error: `${file} is not valid YAML: ${(error as Error).message}` }
  }
  const value = document?.catalog_root
  if (value === undefined || value === null) return {}
  if (typeof value !== 'string' || value.length === 0) {
    return { error: `${file} declares a \`catalog_root\` that is not a non-empty string` }
  }
  return { path: value }
}

export function resolveCatalogRoot(argument?: string): RootResolution {
  let candidate: string | undefined
  let source: RootSource
  if (argument) {
    candidate = argument
    source = 'argument'
  } else if (process.env.APIMANAC_CATALOG) {
    candidate = process.env.APIMANAC_CATALOG
    source = 'environment'
  } else {
    const configured = readConfigRoot()
    if (configured.error) {
      return { ok: false, code: 'config_unreadable', message: configured.error }
    }
    candidate = configured.path
    source = 'config'
  }

  if (!candidate) {
    return {
      ok: false,
      code: 'not_configured',
      message: `no catalog root is configured. Set one of: ${ROOT_PRECEDENCE}. The working directory is never used.`,
    }
  }

  // Relative paths resolve against the process cwd only as a spelling of an
  // absolute path the user supplied; they never trigger a search.
  const path = isAbsolute(candidate) ? candidate : resolve(candidate)

  if (!existsSync(path) || !statSync(path).isDirectory()) {
    return {
      ok: false,
      code: 'not_a_directory',
      message: `the configured catalog root \`${path}\` is not a directory`,
      path,
    }
  }

  const manifestPath = join(path, 'catalog', 'manifest.yaml')
  if (!existsSync(manifestPath)) {
    return {
      ok: false,
      code: 'manifest_missing',
      message: `the configured catalog root \`${path}\` does not contain catalog/manifest.yaml`,
      path,
    }
  }

  const git = GitContext.open(path)
  return {
    ok: true,
    path,
    source,
    manifestPath,
    git,
    noSnapshotReason: git.unavailableReason,
  }
}
