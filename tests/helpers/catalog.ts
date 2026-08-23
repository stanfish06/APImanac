import { cpSync } from 'node:fs'
import { loadCommitted, loadWorkingTree } from '../../src/catalog/load'
import { resolveCatalogRoot, type CatalogRoot } from '../../src/catalog/root'
import { TempRepo, fixtureManifest } from './repo'

export const REPO_ROOT = Bun.fileURLToPath(new URL('../..', import.meta.url))

/** A temp repo carrying a minimal committed catalog. */
export function catalogRepo(): TempRepo {
  const repo = TempRepo.create()
  repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
  return repo
}

/** Repository-relative root of the example catalog CI grades against. */
export const STARTER_ROOT = `${REPO_ROOT}/examples/starter`

/** A temp repo carrying a copy of the starter catalog. */
export function starterCatalogRepo(): TempRepo {
  const repo = TempRepo.create()
  cpSync(`${STARTER_ROOT}/catalog`, repo.path('catalog'), { recursive: true })
  return repo
}

export function openRoot(path: string): CatalogRoot {
  const resolution = resolveCatalogRoot(path)
  if (!resolution.ok) throw new Error(`fixture root did not resolve: ${resolution.message}`)
  return resolution
}

export function workingTreeOf(path: string) {
  const root = openRoot(path)
  return { root, snapshot: loadWorkingTree(root.path, root.git) }
}

export function committedOf(path: string) {
  const root = openRoot(path)
  return { root, snapshot: loadCommitted(root.git) }
}
