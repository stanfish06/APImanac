import { cpSync } from 'node:fs'
import { afterEach, describe, expect, test } from 'bun:test'
import { loadWorkingTree } from '../../src/catalog/load'
import { formatFinding, validateCatalog } from '../../src/catalog/validate'
import { openRoot } from '../helpers/catalog'
import { TempRepo } from '../helpers/repo'
import { fixturePath } from '../helpers/yaml'

/** Each fixture is a whole mini-catalog exercising one integrity failure. */
const CASES: [directory: string, kind: string, expectation: string][] = [
  ['id-format', 'schema', 'kebab'],
  ['alias-collision', 'alias_collision', 'shared-alias'],
  ['merge-cycle', 'merge_cycle', 'one -> two -> one'],
  ['merge-dangling', 'merge_dangling', 'nowhere'],
  ['cross-source-composition', 'schema', 'atomic contract'],
  ['missing-api-reference', 'missing_api_reference', 'ghost'],
  ['tracked-secret', 'tracked_secret', 'environment-variable name'],
  ['filename-mismatch', 'filename_mismatch', 'actual-id'],
  ['unknown-source', 'unknown_source', 'not-declared'],
  ['unsupported-schema-version', 'unsupported_schema_version', 'apimanac migrate'],
  ['evidence-mismatch', 'evidence_mismatch', 'apimanac verify'],
  ['dangling-profile-link', 'dangling_profile_link', 'absent'],
]

const repos: TempRepo[] = []

function loadCase(directory: string) {
  const repo = TempRepo.create()
  repos.push(repo)
  cpSync(fixturePath('invalid', directory, 'catalog'), repo.path('catalog'), { recursive: true })
  repo.commit(`invalid fixture ${directory}`)
  const root = openRoot(repo.root)
  return validateCatalog(loadWorkingTree(root.path, root.git))
}

afterEach(() => {
  while (repos.length) repos.pop()?.dispose()
})

describe('validate reports each contract violation with its typed kind', () => {
  test.each(CASES)('%s produces a %s finding', (directory, kind, expectation) => {
    const report = loadCase(directory)
    expect(report.ok).toBe(false)
    const matching = report.findings.filter((finding) => finding.kind === kind)
    expect(matching.length).toBeGreaterThan(0)
    expect(matching.map(formatFinding).join('\n')).toContain(expectation)
  })

  test('every finding names a file', () => {
    for (const [directory] of CASES) {
      for (const finding of loadCase(directory).findings) {
        expect(finding.file).not.toBe('')
      }
    }
  })

  test('all findings are reported, not only the first', () => {
    const repo = TempRepo.create()
    repos.push(repo)
    cpSync(fixturePath('invalid', 'alias-collision', 'catalog'), repo.path('catalog'), {
      recursive: true,
    })
    cpSync(fixturePath('invalid', 'merge-dangling', 'catalog', 'meta'), repo.path('catalog/meta'), {
      recursive: true,
    })
    repo.commit('two independent failures')
    const root = openRoot(repo.root)
    const report = validateCatalog(loadWorkingTree(root.path, root.git))
    const kinds = new Set(report.findings.map((finding) => finding.kind))
    expect(kinds.has('alias_collision')).toBe(true)
    expect(kinds.has('merge_dangling')).toBe(true)
  })

  test('a tracked secret finding never echoes the matched value', () => {
    const report = loadCase('tracked-secret')
    const text = report.findings.map(formatFinding).join('\n')
    expect(text).not.toContain('LEAKY_API_TOKEN')
  })
})
