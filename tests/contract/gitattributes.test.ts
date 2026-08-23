import { readFileSync } from 'node:fs'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { TempRepo } from '../helpers/repo'

/**
 * Authority is a byte comparison between the worktree file and its `HEAD` blob.
 * A content filter that rewrote line endings would make a clean file look dirty
 * (or a dirty one look clean), so `catalog/**` is marked `-text`.
 */
describe('catalog files pass through no content filter', () => {
  let repo: TempRepo

  beforeEach(() => {
    repo = TempRepo.create()
  })

  afterEach(() => repo.dispose())

  test('the repository ships a .gitattributes marking catalog/** as -text', () => {
    const attributes = readFileSync(
      Bun.fileURLToPath(new URL('../../.gitattributes', import.meta.url)),
      'utf8',
    )
    expect(attributes).toContain('catalog/** -text')
  })

  test('CRLF content round-trips byte-identically through commit and checkout', () => {
    // `core.autocrlf=input` is the setting that would rewrite bytes on commit.
    repo.git('config', 'core.autocrlf', 'input')
    const crlf = 'id: example\r\nname: Example\r\n'
    repo.write('catalog/meta/example.yaml', crlf)
    repo.commit('add catalog record with CRLF')

    const committed = repo.git('cat-file', 'blob', 'HEAD:catalog/meta/example.yaml')
    expect(committed).toBe(crlf)

    repo.remove('catalog/meta/example.yaml')
    repo.git('checkout', '--', 'catalog/meta/example.yaml')
    expect(readFileSync(repo.path('catalog/meta/example.yaml'), 'utf8')).toBe(crlf)
    expect(repo.git('status', '--porcelain')).toBe('')
  })

  test('an unprotected path is rewritten by the same setting, showing the filter is real', () => {
    repo.git('config', 'core.autocrlf', 'input')
    const crlf = 'a\r\nb\r\n'
    repo.write('notes.txt', crlf)
    repo.commit('add unprotected file')
    expect(repo.git('cat-file', 'blob', 'HEAD:notes.txt')).toBe('a\nb\n')
  })
})
