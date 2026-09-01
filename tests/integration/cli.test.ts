import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { afterEach, beforeEach, describe, expect, test } from 'bun:test'
import { COMMANDS, USAGE, parseArgs, runCli, type Io } from '../../src/cli'
import { EXIT_CODES } from '../../src/errors'
import { contractHash } from '../../src/catalog/canonical'
import { resetXdgForTests } from '../../src/paths'
import { evaluateEligibility } from '../../src/policy/eligibility'
import { evaluatePermission } from '../../src/policy/permissions'
import { ExecutionProfile } from '../../src/schema/execution'
import { openRoot, starterCatalogRepo } from '../helpers/catalog'
import type { TempRepo } from '../helpers/repo'

let repo: TempRepo
let scratch: string

function capture(): Io & { out: (text: string) => void; stdout: string[]; stderr: string[] } {
  const stdout: string[] = []
  const stderr: string[] = []
  return {
    stdout,
    stderr,
    out: (text: string) => stdout.push(text),
    err: (text: string) => stderr.push(text),
  }
}

async function run(argv: string[]) {
  const io = capture()
  const code = await runCli(argv, io)
  return { code, stdout: io.stdout.join('\n'), stderr: io.stderr.join('\n') }
}

beforeEach(() => {
  repo = starterCatalogRepo()
  repo.commit('seed catalog')
  scratch = mkdtempSync(join(tmpdir(), 'apimanac-cli-'))
  process.env.XDG_CACHE_HOME = join(scratch, 'cache')
  process.env.XDG_STATE_HOME = join(scratch, 'state')
  process.env.XDG_CONFIG_HOME = join(scratch, 'config')
  process.env.XDG_DATA_HOME = join(scratch, 'data')
  delete process.env.APIMANAC_CATALOG
  resetXdgForTests()
})

afterEach(() => {
  repo.dispose()
  rmSync(scratch, { recursive: true, force: true })
  resetXdgForTests()
})

describe('the command surface is exactly the declared set', () => {
  test('help lists exactly the declared commands', async () => {
    const { code, stdout } = await run(['--help'])
    expect(code).toBe(EXIT_CODES.ok)
    for (const name of COMMANDS) expect(stdout).toContain(name)
    expect(stdout).toBe(USAGE)
  })

  test('the declared set is exactly the sixteen declared commands', () => {
    expect([...COMMANDS]).toEqual([
      'build',
      'search',
      'show',
      'add',
      'refresh',
      'validate',
      'migrate',
      'auth status',
      'call',
      'verify',
      'workflow run',
      'script run',
      'cache list',
      'cache clear',
      'cache prune',
      'mcp',
    ])
  })

  test.each([
    'edit',
    'review',
    'commit',
    'promote',
    'vault',
  ])('the undeclared command `%s` is an unknown-command error', async (name) => {
    const { code, stderr } = await run([name])
    expect(code).toBe(EXIT_CODES.usage)
    expect(stderr).toContain('unknown_command')
  })

  test('help documents the workflow and script commands', async () => {
    const { stdout } = await run(['--help'])
    expect(stdout).toContain('workflow run')
    expect(stdout).toContain('script run')
    const workflowHelp = await run(['workflow', 'run', '--help'])
    expect(workflowHelp.stdout).toContain('<api-id>/<workflow-id>')
  })

  test('workflow run needs an api/workflow target', async () => {
    const { code, stderr } = await run(['--catalog', repo.root, 'workflow', 'run', 'bare'])
    expect(code).toBe(EXIT_CODES.usage)
    expect(stderr).toContain('<api-id>/<workflow-id>')
  })

  test('script run needs at least one --bind', async () => {
    const file = join(scratch, 'x.ts')
    writeFileSync(file, 'export default async function run() { return 1 }')
    const { code, stderr } = await run(['--catalog', repo.root, 'script', 'run', file])
    expect(code).toBe(EXIT_CODES.usage)
    expect(stderr).toContain('--bind')
  })

  test('a two-word command parses as one command', () => {
    expect(parseArgs(['auth', 'status']).command).toBe('auth status')
    expect(parseArgs(['cache', 'prune']).command).toBe('cache prune')
  })

  test('flags parse in both `--name value` and `--name=value` forms', () => {
    expect(parseArgs(['validate', '--catalog', '/x']).flags.catalog).toBe('/x')
    expect(parseArgs(['validate', '--catalog=/y']).flags.catalog).toBe('/y')
    expect(parseArgs(['validate', '--json']).flags.json).toBe(true)
  })
})

describe('catalog root resolution', () => {
  test('an unset root exits non-zero naming the three ways to set it', async () => {
    const { code, stderr } = await run(['validate'])
    expect(code).toBe(EXIT_CODES.error)
    expect(stderr).toContain('--catalog')
    expect(stderr).toContain('APIMANAC_CATALOG')
    expect(stderr).toContain('catalog_root')
  })

  test('a directory containing catalog/manifest.yaml is still not discovered', async () => {
    const cwd = mkdtempSync(join(tmpdir(), 'apimanac-cwd-'))
    mkdirSync(join(cwd, 'catalog'), { recursive: true })
    writeFileSync(
      join(cwd, 'catalog', 'manifest.yaml'),
      'catalog_name: hijack\nschema_version: 1\n',
    )
    const previous = process.cwd()
    process.chdir(cwd)
    try {
      const { code } = await run(['validate'])
      expect(code).toBe(EXIT_CODES.error)
    } finally {
      process.chdir(previous)
      rmSync(cwd, { recursive: true, force: true })
    }
  })

  test('the environment value resolves the root', async () => {
    process.env.APIMANAC_CATALOG = repo.root
    const { code, stdout } = await run(['validate'])
    expect(code).toBe(EXIT_CODES.ok)
    expect(stdout).toContain('no findings')
  })

  test('a root missing its manifest names the resolved path and the missing file', async () => {
    const bare = mkdtempSync(join(tmpdir(), 'apimanac-bare-'))
    try {
      const { code, stderr } = await run(['validate', '--catalog', bare])
      expect(code).toBe(EXIT_CODES.error)
      expect(stderr).toContain(bare)
      expect(stderr).toContain('catalog/manifest.yaml')
    } finally {
      rmSync(bare, { recursive: true, force: true })
    }
  })
})

describe('validate', () => {
  test('a clean catalog exits zero', async () => {
    const { code, stdout } = await run(['validate', '--catalog', repo.root])
    expect(code).toBe(EXIT_CODES.ok)
    expect(stdout).toContain('no findings')
  })

  test('a broken catalog exits non-zero reporting each finding with its kind and file', async () => {
    repo.writeYaml('catalog/meta/broken.yaml', { id: 'Broken_Id', name: 'Broken' })
    const { code, stdout, stderr } = await run(['validate', '--catalog', repo.root])
    expect(code).toBe(EXIT_CODES.error)
    expect(stdout).toContain('schema:')
    expect(stdout).toContain('catalog/meta/broken.yaml')
    expect(stderr).toContain('validation_failed')
  })

  test('machine-readable failure carries the typed kind and a non-zero exit', async () => {
    repo.writeYaml('catalog/meta/broken.yaml', { id: 'Broken_Id', name: 'Broken' })
    const { code, stdout } = await run(['validate', '--catalog', repo.root, '--json'])
    expect(code).toBe(EXIT_CODES.error)
    const parsed = JSON.parse(stdout) as { ok: boolean; error: { kind: string } }
    expect(parsed.ok).toBe(false)
    expect(parsed.error.kind).toBe('validation_failed')
  })

  test('machine-readable output parses as one document with no progress text', async () => {
    const { stdout } = await run(['validate', '--catalog', repo.root, '--json'])
    const parsed = JSON.parse(stdout) as { ok: boolean; findings: unknown[] }
    expect(parsed.ok).toBe(true)
    expect(parsed.findings).toEqual([])
  })
})

describe('build and search', () => {
  test('build writes the store under the XDG cache root', async () => {
    const { code, stdout } = await run(['build', '--catalog', repo.root, '--json'])
    expect(code).toBe(EXIT_CODES.ok)
    const parsed = JSON.parse(stdout) as { path: string; indexRows: number; offline: boolean }
    expect(parsed.path).toContain(join(scratch, 'cache', 'apimanac'))
    expect(parsed.indexRows).toBe(5)
    expect(existsSync(parsed.path)).toBe(true)
  })

  test('an offline build succeeds and reports it', async () => {
    const { stdout } = await run(['build', '--catalog', repo.root, '--offline', '--json'])
    expect((JSON.parse(stdout) as { offline: boolean }).offline).toBe(true)
  })

  test('build refuses when validation fails', async () => {
    repo.writeYaml('catalog/meta/broken.yaml', { id: 'Broken_Id', name: 'Broken' })
    const { code, stderr } = await run(['build', '--catalog', repo.root])
    expect(code).toBe(EXIT_CODES.error)
    expect(stderr).toContain('validation_failed')
  })

  test('search returns machine-readable results with no endpoints or credentials', async () => {
    const { code, stdout } = await run(['search', '--catalog', repo.root, '--json', 'scholarly'])
    expect(code).toBe(EXIT_CODES.ok)
    const parsed = JSON.parse(stdout) as { results: { id: string }[] }
    expect(parsed.results[0]?.id).toBe('openalex')
    expect(stdout).not.toContain('api.openalex.org')
    expect(stdout).not.toContain('/works/**')
  })

  test('an unknown filter value is a typed usage error naming the allowed values', async () => {
    const { code, stdout } = await run([
      'search',
      '--catalog',
      repo.root,
      '--json',
      '--lifecycle',
      'zombie',
      'anything',
    ])
    expect(code).toBe(EXIT_CODES.usage)
    const parsed = JSON.parse(stdout) as { error: { kind: string; detail: { allowed: string[] } } }
    expect(parsed.error.kind).toBe('usage')
    expect(parsed.error.detail.allowed).toContain('deprecated')
  })
})

describe('show', () => {
  test('a lookup by alias reports the canonical record and the alias used', async () => {
    const { code, stdout } = await run(['show', '--catalog', repo.root, '--json', 'open-alex'])
    expect(code).toBe(EXIT_CODES.ok)
    const parsed = JSON.parse(stdout) as { id: string; matched_alias: string }
    expect(parsed.id).toBe('openalex')
    expect(parsed.matched_alias).toBe('open-alex')
  })

  test('an unknown id is a typed not-found with no partial record', async () => {
    const { code, stdout } = await run(['show', '--catalog', repo.root, '--json', 'nope'])
    expect(code).toBe(EXIT_CODES.error)
    const parsed = JSON.parse(stdout) as { ok: boolean; error: { kind: string } }
    expect(parsed.ok).toBe(false)
    expect(parsed.error.kind).toBe('not_found')
  })

  test('the human output prints the fingerprint an operator pastes into grants.yaml', async () => {
    const { stdout } = await run(['show', '--catalog', repo.root, 'github'])
    expect(stdout).toMatch(/authority fingerprint: v1:sha256:[0-9a-f]{64}/)
    expect(stdout).toMatch(/contract hash: {8}v1:sha256:[0-9a-f]{64}/)
  })

  test('show needs an id', async () => {
    const { code, stderr } = await run(['show', '--catalog', repo.root])
    expect(code).toBe(EXIT_CODES.usage)
    expect(stderr).toContain('needs an API id')
  })
})

describe('auth status', () => {
  test('with no grants file it reports every auth profile and exits zero', async () => {
    const { code, stdout } = await run(['auth', 'status', '--catalog', repo.root, '--json'])
    expect(code).toBe(EXIT_CODES.ok)
    const parsed = JSON.parse(stdout) as {
      grants_file_present: boolean
      profiles: { profile_id: string; readiness: string }[]
    }
    expect(parsed.grants_file_present).toBe(false)
    expect(parsed.profiles.every((profile) => profile.readiness === 'no_grant')).toBe(true)
  })

  test('output contains no credential value, variable name or credential path', async () => {
    const { stdout } = await run(['auth', 'status', '--catalog', repo.root, '--json'])
    expect(stdout).not.toContain('GITHUB_TOKEN')
    expect(stdout).not.toContain('credentials/')
  })
})

describe('call', () => {
  test('a call needs a path', async () => {
    const { code, stderr } = await run(['call', '--catalog', repo.root, 'openalex'])
    expect(code).toBe(EXIT_CODES.usage)
    expect(stderr).toContain('--path')
  })

  test('a candidate profile is a policy refusal distinct from a transport error', async () => {
    const { code, stdout } = await run([
      'call',
      '--catalog',
      repo.root,
      '--json',
      '--profile',
      'public',
      '--path',
      '/works',
      'openalex',
    ])
    expect(code).toBe(EXIT_CODES.policy)
    const parsed = JSON.parse(stdout) as { error: { kind: string; message: string } }
    expect(parsed.error.kind).toBe('profile_ineligible')
    expect(parsed.error.message).toContain('apimanac verify')
  })

  test('a denied operation exits with the policy code, not the transport one', async () => {
    const { code, stdout } = await run([
      'call',
      '--catalog',
      repo.root,
      '--json',
      '--profile',
      'public',
      '--method',
      'DELETE',
      '--path',
      '/works',
      'openalex',
    ])
    expect(code).toBe(EXIT_CODES.policy)
    expect(code).not.toBe(EXIT_CODES.transport)
    const parsed = JSON.parse(stdout) as { error: { kind: string } }
    expect(['operation_denied', 'profile_ineligible']).toContain(parsed.error.kind)
  })

  test('no approval flag authorizes a confirm operation on an eligible profile', async () => {
    // The route must be genuinely `confirm` on a genuinely eligible profile, or
    // this test would pass on an ineligibility refusal and never exercise the
    // approval path at all.
    const profile = {
      profile_id: 'confirmable',
      api_id: 'openalex',
      origins: ['https://api.openalex.org'],
      auth: { type: 'none' },
      permissions: [{ method: 'GET', path: '/works/**', decision: 'auto' }],
      health_probe: { method: 'GET', path: '/works', expect_status: 200 },
    }
    const candidate = ExecutionProfile.parse(profile)
    repo.writeYaml('catalog/execution/openalex/confirmable.yaml', {
      ...profile,
      verification: {
        state: 'verified',
        verified_at: '2026-01-01T00:00:00Z',
        evidence: {
          contract_hash: contractHash(candidate),
          method: 'GET',
          path: '/works',
          status: 200,
          response_hash: `v1:sha256:${'0'.repeat(64)}`,
          timestamp: '2026-01-01T00:00:00Z',
          tool_version: '0.0.0',
        },
      },
    })
    repo.commit('add an eligible profile with a confirm route')

    const eligible = evaluateEligibility(openRoot(repo.root), 'openalex', 'confirmable')
    expect(eligible.eligible).toBe(true)
    // `/authors` matches no rule, so it resolves to `confirm`.
    expect(
      evaluatePermission((eligible as { profile: ExecutionProfile }).profile, 'GET', '/authors')
        .decision,
    ).toBe('confirm')

    const { code, stdout } = await run([
      'call',
      '--catalog',
      repo.root,
      '--json',
      '--approved',
      '--yes',
      '--force',
      '--confirm',
      '--profile',
      'confirmable',
      '--path',
      '/authors',
      'openalex',
    ])
    expect(code).toBe(EXIT_CODES.policy)
    const parsed = JSON.parse(stdout) as { ok: boolean; error: { kind: string } }
    expect(parsed.ok).toBe(false)
    expect(parsed.error.kind).toBe('confirmation_required')
  })
})

describe('cache commands', () => {
  test('an empty cache lists nothing', async () => {
    const { code, stdout } = await run(['cache', 'list', '--json'])
    expect(code).toBe(EXIT_CODES.ok)
    const parsed = JSON.parse(stdout) as { entries: unknown[]; bytes: number }
    expect(parsed.entries).toEqual([])
    expect(parsed.bytes).toBe(0)
  })

  test('clear and prune report what they did', async () => {
    expect(
      (JSON.parse((await run(['cache', 'clear', '--json'])).stdout) as { removed: number }).removed,
    ).toBe(0)
    const pruned = JSON.parse((await run(['cache', 'prune', '--json'])).stdout) as {
      expired: number
      evicted: number
    }
    expect(pruned.expired).toBe(0)
    expect(pruned.evicted).toBe(0)
  })

  test('the cache lives under the XDG cache root, not the working directory', async () => {
    await run(['cache', 'list', '--json'])
    expect(existsSync(join(scratch, 'cache', 'apimanac', 'responses'))).toBe(true)
  })
})

describe('exit codes distinguish failure kinds', () => {
  test('the declared codes are distinct', () => {
    const values = Object.values(EXIT_CODES)
    expect(new Set(values).size).toBe(values.length)
    expect(EXIT_CODES.ok).toBe(0)
  })

  test('a succeeding command exits zero', async () => {
    expect((await run(['validate', '--catalog', repo.root])).code).toBe(0)
  })
})
