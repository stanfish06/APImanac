import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { parse } from 'yaml'
import { join } from 'node:path'
import { GrantStore } from '../../src/auth/grants'
import { authorityFingerprint, contractHash } from '../../src/catalog/canonical'
import { profilePath } from '../../src/catalog/load'
import type { CatalogRoot } from '../../src/catalog/root'
import { ApprovalTokens, type ConfirmationChannel } from '../../src/execute/confirm'
import { HealthStore } from '../../src/execute/health'
import { injectedProvider } from '../../src/auth/providers'
import { ExecutionProfile } from '../../src/schema/execution'
import type { CallServices } from '../../src/execute/call'
import { startMockServer, type MockServer } from '../fixtures/http/mock-server'
import { openRoot } from './catalog'
import { TempRepo, fixtureManifest } from './repo'

/**
 * A committed catalog whose profile points at a local mock. The mock binds
 * `127.0.0.1`, so the profile declares a private network scope — the same
 * fixtures prove both that a scoped profile reaches it and that an unscoped one
 * cannot.
 */

export interface ExecutionFixture {
  readonly repo: TempRepo
  readonly root: CatalogRoot
  readonly mock: MockServer
  readonly peer: MockServer
  readonly grantsPath: string
  readonly healthPath: string
  readonly cacheDir: string
  reopen(): CatalogRoot
  services(overrides?: Partial<CallServices>): CallServices
  writeProfile(profileId: string, overrides: Record<string, unknown>, verify?: boolean): void
  dispose(): Promise<void>
}

export interface FixtureOptions {
  readonly slowMs?: number
  readonly largeBytes?: number
}

export async function executionFixture(options: FixtureOptions = {}): Promise<ExecutionFixture> {
  const peer = await startMockServer()
  const mock = await startMockServer({
    peer,
    slowMs: options.slowMs,
    largeBytes: options.largeBytes,
  })
  const repo = TempRepo.create()
  const scratch = mkdtempSync(join(tmpdir(), 'apimanac-exec-'))
  const grantsPath = join(scratch, 'grants.yaml')
  const healthPath = join(scratch, 'health.db')
  const cacheDir = join(scratch, 'responses')

  repo.writeYaml('catalog/manifest.yaml', fixtureManifest())
  repo.writeYaml('catalog/meta/mock.yaml', {
    id: 'mock',
    name: 'Local mock',
    description: 'The local mock server every execution test runs against.',
    aliases: ['mock-api'],
    profiles: ['public', 'keyed', 'basic', 'twoorigin', 'unscoped', 'draft'],
  })

  const fixture: ExecutionFixture = {
    repo,
    mock,
    peer,
    grantsPath,
    healthPath,
    cacheDir,
    get root() {
      return openRoot(repo.root)
    },
    reopen: () => openRoot(repo.root),
    services(overrides = {}) {
      return {
        grants: GrantStore.load({ path: grantsPath, provider: injectedProvider({}) }),
        tokens: new ApprovalTokens('test-session'),
        health: HealthStore.open(healthPath),
        ...overrides,
      }
    },
    writeProfile(profileId, overrides, verify = true) {
      writeProfile(repo, mock, peer, profileId, overrides, verify)
    },
    async dispose() {
      repo.dispose()
      rmSync(scratch, { recursive: true, force: true })
      await mock.close()
      await peer.close()
    },
  }

  writeProfile(repo, mock, peer, 'public', {}, true)
  writeProfile(
    repo,
    mock,
    peer,
    'keyed',
    {
      auth: {
        type: 'bearer',
        credential_id: 'mock-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      permissions: [
        { method: 'GET', path: '/auth', decision: 'auto' },
        { method: 'GET', path: '/echo-credential', decision: 'auto' },
        { method: 'GET', path: '/echo-credential-header', decision: 'auto' },
        { method: 'GET', path: '/echo-credential-split', decision: 'auto' },
        { method: 'GET', path: '/redirect/**', decision: 'auto' },
        { method: 'POST', path: '/echo', decision: 'confirm' },
        { method: 'DELETE', path: '/**', decision: 'deny' },
      ],
    },
    true,
  )
  writeProfile(
    repo,
    mock,
    peer,
    'basic',
    {
      auth: {
        type: 'basic',
        credential_id: 'mock-basic',
        components: [{ name: 'username' }, { name: 'password' }],
        placements: [{ kind: 'basic', username: 'username', password: 'password' }],
      },
      permissions: [
        { method: 'GET', path: '/auth', decision: 'auto' },
        { method: 'DELETE', path: '/**', decision: 'deny' },
      ],
    },
    true,
  )
  writeProfile(
    repo,
    mock,
    peer,
    'twoorigin',
    {
      origins: [mock.origin, peer.origin],
      permissions: [
        { method: 'GET', path: '/ok', decision: 'auto' },
        { method: 'GET', path: '/redirect/**', decision: 'auto' },
        { method: 'DELETE', path: '/**', decision: 'deny' },
      ],
    },
    true,
  )
  writeProfile(repo, mock, peer, 'unscoped', { network_scope: 'public' }, true)
  repo.commit('committed execution fixtures')
  writeProfile(repo, mock, peer, 'draft', {}, true)

  return fixture
}

function writeProfile(
  repo: TempRepo,
  mock: MockServer,
  peer: MockServer,
  profileId: string,
  overrides: Record<string, unknown>,
  verify: boolean,
): void {
  const draft: Record<string, unknown> = {
    profile_id: profileId,
    api_id: 'mock',
    origins: [mock.origin],
    auth: { type: 'none' },
    network_scope: 'private',
    permissions: [
      { method: 'GET', path: '/ok', decision: 'auto' },
      { method: 'GET', path: '/echo', decision: 'auto' },
      { method: 'GET', path: '/large', decision: 'auto' },
      { method: 'GET', path: '/slow', decision: 'auto' },
      { method: 'GET', path: '/compressed', decision: 'auto' },
      { method: 'GET', path: '/compressed-bomb', decision: 'auto' },
      { method: 'GET', path: '/cookies', decision: 'auto' },
      { method: 'GET', path: '/instructions', decision: 'auto' },
      { method: 'GET', path: '/status/*', decision: 'auto' },
      { method: 'GET', path: '/redirect/**', decision: 'auto' },
      { method: 'POST', path: '/echo', decision: 'confirm' },
      { method: 'DELETE', path: '/**', decision: 'deny' },
    ],
    response: { allowed_headers: ['x-ratelimit-remaining'] },
    health_probe: { method: 'GET', path: '/ok', expect_status: 200 },
    cache: { enabled: false },
    verification: { state: 'candidate' },
    ...overrides,
  }
  void peer
  if (verify) {
    const candidate = ExecutionProfile.parse(draft)
    draft.verification = {
      state: 'verified',
      verified_at: '2026-02-01T00:00:00Z',
      evidence: {
        contract_hash: contractHash(candidate),
        method: 'GET',
        path: '/ok',
        status: 200,
        response_hash: `v1:sha256:${'0'.repeat(64)}`,
        timestamp: '2026-02-01T00:00:00Z',
        tool_version: '0.0.0',
      },
    }
  }
  ExecutionProfile.parse(draft)
  repo.writeYaml(profilePath('mock', profileId), draft)
}

/** The fingerprint an operator would paste into `grants.yaml`. */
export function fingerprintOf(repo: TempRepo, profileId: string): string {
  return authorityFingerprint(readProfile(repo, profileId))
}

export function readProfile(repo: TempRepo, profileId: string): ExecutionProfile {
  const file = repo.path(profilePath('mock', profileId))
  return ExecutionProfile.parse(parse(readFileSync(file, 'utf8')))
}

export function alwaysAccept(): ConfirmationChannel {
  return { label: 'test', confirm: async () => true }
}

export function alwaysDecline(): ConfirmationChannel {
  return { label: 'test', confirm: async () => false }
}
