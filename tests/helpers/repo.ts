import { execFileSync } from 'node:child_process'
import { mkdtempSync, mkdirSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join } from 'node:path'
import { stringify } from 'yaml'

/**
 * A throwaway Git repository holding a catalog. Authority checks compare
 * worktree bytes to `HEAD` blobs, so tests need real commits.
 */
export class TempRepo {
  readonly root: string

  private constructor(root: string) {
    this.root = root
  }

  static create(): TempRepo {
    const root = mkdtempSync(join(tmpdir(), 'apimanac-repo-'))
    const repo = new TempRepo(root)
    repo.git('init', '--initial-branch', 'main')
    repo.git('config', 'user.email', 'fixture@example.invalid')
    repo.git('config', 'user.name', 'Fixture')
    repo.git('config', 'commit.gpgsign', 'false')
    repo.write('.gitattributes', 'catalog/** -text\n')
    return repo
  }

  git(...args: string[]): string {
    return execFileSync('git', ['-C', this.root, ...args], { encoding: 'utf8' })
  }

  path(relative: string): string {
    return join(this.root, relative)
  }

  write(relative: string, contents: string): void {
    const target = this.path(relative)
    mkdirSync(dirname(target), { recursive: true })
    writeFileSync(target, contents)
  }

  writeYaml(relative: string, value: unknown): void {
    this.write(relative, stringify(value))
  }

  /** Stage and commit everything currently in the worktree. */
  commit(message = 'fixture'): string {
    this.git('add', '-A')
    this.git('commit', '-m', message, '--allow-empty')
    return this.git('rev-parse', 'HEAD').trim()
  }

  remove(relative: string): void {
    rmSync(this.path(relative), { force: true })
  }

  dispose(): void {
    rmSync(this.root, { recursive: true, force: true })
  }
}

/** The default manifest every catalog fixture starts from. */
export function fixtureManifest(sources: unknown[] = []): unknown {
  return {
    catalog_name: 'apimanac-test',
    schema_version: 1,
    sources,
    lifecycle_vocabulary: ['active', 'deprecated', 'gone', 'merged'],
    curation_vocabulary: ['imported', 'curated'],
  }
}
