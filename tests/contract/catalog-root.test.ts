import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { GitContext } from '../../src/catalog/git'
import { ROOT_PRECEDENCE, resolveCatalogRoot } from '../../src/catalog/root'
import { resetXdgForTests } from '../../src/paths'
import { catalogRepo } from '../helpers/catalog'
import { TempRepo, fixtureManifest } from '../helpers/repo'

const SAVED_ENV = { ...process.env }

function clearEnv(): void {
  process.env.APIMANAC_CATALOG = undefined
  delete process.env.APIMANAC_CATALOG
  resetXdgForTests()
}

describe('catalog root resolution', () => {
  let repo: TempRepo
  let cwd: string

  beforeEach(() => {
    repo = catalogRepo()
    repo.commit('seed')
    cwd = mkdtempSync(join(tmpdir(), 'apimanac-cwd-'))
    clearEnv()
  })

  afterEach(() => {
    repo.dispose()
    rmSync(cwd, { recursive: true, force: true })
    process.env = { ...SAVED_ENV }
    resetXdgForTests()
  })

  test('an explicit --catalog argument wins', () => {
    const resolution = resolveCatalogRoot(repo.root)
    expect(resolution.ok).toBe(true)
    if (resolution.ok) {
      expect(resolution.source).toBe('argument')
      expect(resolution.path).toBe(repo.root)
    }
  })

  test('the environment value is used when no argument is given', () => {
    process.env.APIMANAC_CATALOG = repo.root
    const resolution = resolveCatalogRoot()
    expect(resolution.ok).toBe(true)
    if (resolution.ok) expect(resolution.source).toBe('environment')
  })

  test('the config key is used when neither argument nor environment is set', () => {
    const configHome = mkdtempSync(join(tmpdir(), 'apimanac-config-'))
    mkdirSync(join(configHome, 'apimanac'), { recursive: true })
    writeFileSync(join(configHome, 'apimanac', 'config.yaml'), `catalog_root: ${repo.root}\n`)
    process.env.XDG_CONFIG_HOME = configHome
    resetXdgForTests()
    try {
      const resolution = resolveCatalogRoot()
      expect(resolution.ok).toBe(true)
      if (resolution.ok) expect(resolution.source).toBe('config')
    } finally {
      rmSync(configHome, { recursive: true, force: true })
    }
  })

  test('an unset root fails naming the precedence and never falls back to the cwd', () => {
    const resolution = resolveCatalogRoot()
    expect(resolution.ok).toBe(false)
    if (!resolution.ok) {
      expect(resolution.code).toBe('not_configured')
      expect(resolution.message).toContain(ROOT_PRECEDENCE)
    }
  })

  test('a working directory that itself contains catalog/manifest.yaml is still not used', () => {
    mkdirSync(join(cwd, 'catalog'), { recursive: true })
    writeFileSync(
      join(cwd, 'catalog', 'manifest.yaml'),
      'catalog_name: hijack\nschema_version: 1\n',
    )
    const previous = process.cwd()
    process.chdir(cwd)
    try {
      const resolution = resolveCatalogRoot()
      expect(resolution.ok).toBe(false)
      if (!resolution.ok) expect(resolution.code).toBe('not_configured')
    } finally {
      process.chdir(previous)
    }
  })

  test('a root missing its manifest fails naming the resolved path and the missing file', () => {
    const bare = mkdtempSync(join(tmpdir(), 'apimanac-bare-'))
    try {
      const resolution = resolveCatalogRoot(bare)
      expect(resolution.ok).toBe(false)
      if (!resolution.ok) {
        expect(resolution.code).toBe('manifest_missing')
        expect(resolution.message).toContain(bare)
        expect(resolution.message).toContain('catalog/manifest.yaml')
      }
    } finally {
      rmSync(bare, { recursive: true, force: true })
    }
  })

  test('a root that is not a repository resolves but reports having no reviewed snapshot', () => {
    const plain = mkdtempSync(join(tmpdir(), 'apimanac-plain-'))
    mkdirSync(join(plain, 'catalog'), { recursive: true })
    writeFileSync(
      join(plain, 'catalog', 'manifest.yaml'),
      'catalog_name: plain\nschema_version: 1\n',
    )
    try {
      const resolution = resolveCatalogRoot(plain)
      expect(resolution.ok).toBe(true)
      if (resolution.ok) {
        expect(resolution.git.available).toBe(false)
        expect(resolution.noSnapshotReason).toContain('not inside a Git repository')
      }
    } finally {
      rmSync(plain, { recursive: true, force: true })
    }
  })

  test('a repository with no commits resolves but reports having no reviewed snapshot', () => {
    const fresh = TempRepo.create()
    fresh.writeYaml('catalog/manifest.yaml', fixtureManifest())
    try {
      const resolution = resolveCatalogRoot(fresh.root)
      expect(resolution.ok).toBe(true)
      if (resolution.ok) {
        expect(resolution.git.available).toBe(false)
        expect(resolution.noSnapshotReason).toContain('no commits')
      }
    } finally {
      fresh.dispose()
    }
  })

  test('a non-directory root is rejected', () => {
    const resolution = resolveCatalogRoot(join(repo.root, 'catalog', 'manifest.yaml'))
    expect(resolution.ok).toBe(false)
    if (!resolution.ok) expect(resolution.code).toBe('not_a_directory')
  })
})

describe('git context failure modes refuse rather than defaulting to eligible', () => {
  test('a directory outside any repository reports not_a_repository', () => {
    const plain = mkdtempSync(join(tmpdir(), 'apimanac-norepo-'))
    try {
      const git = GitContext.open(plain)
      expect(git.available).toBe(false)
      expect(git.head).toBeUndefined()
      expect(git.trackedPaths().size).toBe(0)
      expect(git.pathState('catalog/manifest.yaml')).toBe('no_snapshot')
      const blob = git.readHeadBlob('catalog/manifest.yaml')
      expect(blob.present).toBe(false)
    } finally {
      rmSync(plain, { recursive: true, force: true })
    }
  })

  test('a repository with no commits reports no_commits and yields no blobs', () => {
    const fresh = TempRepo.create()
    fresh.writeYaml('catalog/manifest.yaml', fixtureManifest())
    try {
      const git = GitContext.open(fresh.root)
      expect(git.available).toBe(false)
      expect(git.readHeadBlob('catalog/manifest.yaml').present).toBe(false)
      expect(git.pathState('catalog/manifest.yaml')).toBe('no_snapshot')
    } finally {
      fresh.dispose()
    }
  })

  test('a path under a content filter is reported filtered, not clean', () => {
    const repo = TempRepo.create()
    repo.write('.gitattributes', 'catalog/** text eol=lf\n')
    repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
    repo.commit('filtered')
    try {
      const git = GitContext.open(repo.root)
      expect(git.isFiltered('catalog/manifest.yaml')).toBe(true)
      expect(git.pathState('catalog/manifest.yaml')).toBe('filtered')
    } finally {
      repo.dispose()
    }
  })
})
