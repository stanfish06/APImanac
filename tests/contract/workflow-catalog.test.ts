import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { Database } from 'bun:sqlite'
import { afterEach, describe, expect, test } from 'bun:test'
import { loadCommitted, loadWorkingTree, workflowScriptPath } from '../../src/catalog/load'
import { validateCatalog } from '../../src/catalog/validate'
import {
  committedProfilesFor,
  committedWorkflowsFor,
  evaluateWorkflowEligibility,
} from '../../src/policy/eligibility'
import { showRecord } from '../../src/search/show'
import { buildStore, canonicalInputHash } from '../../src/store/build'
import { openRoot } from '../helpers/catalog'
import { TempRepo, fixtureManifest } from '../helpers/repo'
import { writeWorkflow } from '../helpers/workflow'

const SCRIPT = `export default async function run() { return null }\n`

let repos: TempRepo[] = []
let scratches: string[] = []

afterEach(() => {
  for (const repo of repos) repo.dispose()
  for (const scratch of scratches) rmSync(scratch, { recursive: true, force: true })
  repos = []
  scratches = []
})

function catalogWithProfile(): TempRepo {
  const repo = TempRepo.create()
  repos.push(repo)
  repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
  repo.writeYaml('catalog/meta/example.yaml', {
    id: 'example',
    name: 'Example',
    description: 'Fixture API.',
    profiles: ['public'],
  })
  repo.writeYaml('catalog/execution/example/public.yaml', {
    profile_id: 'public',
    api_id: 'example',
    origins: ['https://api.example.com'],
    auth: { type: 'none' },
    permissions: [{ method: 'GET', path: '/**', decision: 'auto' }],
  })
  return repo
}

function scratchDir(): string {
  const dir = mkdtempSync(join(tmpdir(), 'apimanac-wf-store-'))
  scratches.push(dir)
  return dir
}

describe('the execution path grammar partitions profiles from workflows', () => {
  test('a workflow yaml is loaded as a workflow and never as a profile', () => {
    const repo = catalogWithProfile()
    writeWorkflow(repo, {
      apiId: 'example',
      workflowId: 'sweep',
      bindings: ['example/public'],
      script: SCRIPT,
    })
    repo.commit()
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    expect([...snapshot.workflows.keys()]).toEqual(['example/sweep'])
    expect([...snapshot.profiles.keys()]).toEqual(['example/public'])
    expect(snapshot.issues).toEqual([])
    const committed = loadCommitted(root.git)
    expect([...committed.workflows.keys()]).toEqual(['example/sweep'])
    expect(committedProfilesFor(root, 'example')).toEqual(['public'])
    expect(committedWorkflowsFor(root, 'example')).toEqual(['sweep'])
  })

  test('an orphaned definition or script is a finding', () => {
    const repo = catalogWithProfile()
    repo.writeYaml('catalog/execution/example/workflows/lonely.yaml', {
      workflow_id: 'lonely',
      api_id: 'example',
      bindings: [{ profile: 'example/public', blob_sha256: `v1:sha256:${'a'.repeat(64)}` }],
    })
    repo.write('catalog/execution/example/workflows/stray.ts', SCRIPT)
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    const kinds = snapshot.issues.map((issue) => issue.kind)
    expect(kinds.filter((kind) => kind === 'workflow_orphan')).toHaveLength(2)
    expect(snapshot.workflows.size).toBe(0)
  })

  test('a yaml at any other depth under execution is a finding, not a profile', () => {
    const repo = catalogWithProfile()
    repo.writeYaml('catalog/execution/example/extra/nested.yaml', { anything: true })
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    expect(snapshot.issues.map((issue) => issue.kind)).toContain('invalid_execution_path')
    expect(snapshot.profiles.size).toBe(1)
  })

  test('a filename/id mismatch is reported', () => {
    const repo = catalogWithProfile()
    repo.writeYaml('catalog/execution/example/workflows/misnamed.yaml', {
      workflow_id: 'other-name',
      api_id: 'example',
      bindings: [{ profile: 'example/public', blob_sha256: `v1:sha256:${'a'.repeat(64)}` }],
    })
    repo.write('catalog/execution/example/workflows/misnamed.ts', SCRIPT)
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    expect(snapshot.issues.map((issue) => issue.kind)).toContain('filename_mismatch')
  })
})

describe('validation checks bindings against the committed catalog', () => {
  test('a binding to a nonexistent profile is a finding', () => {
    const repo = catalogWithProfile()
    repo.commit()
    writeWorkflow(repo, {
      apiId: 'example',
      workflowId: 'sweep',
      bindings: ['example/public'],
      script: SCRIPT,
    })
    const root = openRoot(repo.root)
    const snapshot = loadWorkingTree(root.path, root.git)
    const workflow = snapshot.workflows.get('example/sweep')
    expect(workflow).toBeDefined()
    // Point the binding at a profile that does not exist.
    repo.writeYaml('catalog/execution/example/workflows/sweep.yaml', {
      workflow_id: 'sweep',
      api_id: 'example',
      bindings: [{ profile: 'example/ghost', blob_sha256: `v1:sha256:${'a'.repeat(64)}` }],
    })
    const report = validateCatalog(loadWorkingTree(root.path, root.git), root.git)
    expect(report.findings.map((finding) => finding.kind)).toContain('dangling_profile_link')
  })

  test('a stale or unpinned binding digest is a finding naming the expected digest', () => {
    const repo = catalogWithProfile()
    repo.commit()
    writeWorkflow(repo, {
      apiId: 'example',
      workflowId: 'sweep',
      bindings: ['example/public'],
      script: SCRIPT,
    })
    // Corrupt the pin.
    repo.writeYaml('catalog/execution/example/workflows/sweep.yaml', {
      workflow_id: 'sweep',
      api_id: 'example',
      bindings: [{ profile: 'example/public', blob_sha256: `v1:sha256:${'b'.repeat(64)}` }],
    })
    const root = openRoot(repo.root)
    const report = validateCatalog(loadWorkingTree(root.path, root.git), root.git)
    const finding = report.findings.find((entry) => entry.kind === 'binding_unpinned')
    expect(finding?.message).toContain('the committed profile blob is v1:sha256:')
  })
})

describe('the derived store covers workflows', () => {
  test('a script-only edit changes the input hash and the store carries workflow rows', () => {
    const repo = catalogWithProfile()
    writeWorkflow(repo, {
      apiId: 'example',
      workflowId: 'sweep',
      bindings: ['example/public'],
      script: SCRIPT,
    })
    repo.commit()
    const root = openRoot(repo.root)
    const storePath = join(scratchDir(), 'catalog.db')
    const before = canonicalInputHash(root)
    buildStore(root, { storePath })

    const db = new Database(storePath, { readonly: true })
    try {
      const rows = db
        .query<{ workflow_id: string; script_file: string }, []>(
          'SELECT workflow_id, script_file FROM d_workflow',
        )
        .all()
      expect(rows).toEqual([
        { workflow_id: 'sweep', script_file: workflowScriptPath('example', 'sweep') },
      ])
      expect(db.query<{ n: number }, []>('SELECT COUNT(*) AS n FROM a_workflow').get()?.n).toBe(1)
    } finally {
      db.close()
    }

    repo.write(workflowScriptPath('example', 'sweep'), `${SCRIPT}// edited\n`)
    expect(canonicalInputHash(openRoot(repo.root))).not.toBe(before)
  })
})

describe('inspection lists workflows without the script body', () => {
  test('show carries the workflow contract, eligibility, and the profile blob digest', () => {
    const repo = catalogWithProfile()
    writeWorkflow(repo, {
      apiId: 'example',
      workflowId: 'sweep',
      bindings: ['example/public'],
      script: SCRIPT,
      description: 'Sweep the seeds.',
    })
    repo.commit()
    const root = openRoot(repo.root)
    const record = showRecord(root, 'example')
    expect(record?.workflows).toHaveLength(1)
    const workflow = record?.workflows[0]
    expect(workflow?.workflow_id).toBe('sweep')
    expect(workflow?.runnable).toBe(true)
    expect(workflow?.bindings[0]?.profile).toBe('example/public')
    expect(JSON.stringify(record)).not.toContain('export default')
    // The value a workflow binding pins is printed beside the profile.
    expect(record?.profiles[0]?.blob_sha256).toBe(workflow?.bindings[0]?.blob_sha256)
  })

  test('an edited script makes the workflow unrunnable with the file named', () => {
    const repo = catalogWithProfile()
    writeWorkflow(repo, {
      apiId: 'example',
      workflowId: 'sweep',
      bindings: ['example/public'],
      script: SCRIPT,
    })
    repo.commit()
    repo.write(workflowScriptPath('example', 'sweep'), `${SCRIPT}// drift\n`)
    const root = openRoot(repo.root)
    const eligibility = evaluateWorkflowEligibility(root, 'example', 'sweep')
    expect(eligibility.eligible).toBe(false)
    if (!eligibility.eligible) {
      expect(eligibility.reasons.join(' ')).toContain(workflowScriptPath('example', 'sweep'))
    }
  })

  test('a re-committed bound profile refuses the workflow until re-pinned', () => {
    const repo = catalogWithProfile()
    writeWorkflow(repo, {
      apiId: 'example',
      workflowId: 'sweep',
      bindings: ['example/public'],
      script: SCRIPT,
    })
    repo.commit()
    repo.writeYaml('catalog/execution/example/public.yaml', {
      profile_id: 'public',
      api_id: 'example',
      description: 'now different bytes',
      origins: ['https://api.example.com'],
      auth: { type: 'none' },
      permissions: [{ method: 'GET', path: '/**', decision: 'auto' }],
    })
    repo.commit('re-commit the bound profile')
    const root = openRoot(repo.root)
    const eligibility = evaluateWorkflowEligibility(root, 'example', 'sweep')
    expect(eligibility.eligible).toBe(false)
    if (!eligibility.eligible) {
      expect(eligibility.reasons.join(' ')).toContain('re-review the workflow')
    }
  })
})
