import { ExecutionProfile } from '../../src/schema/execution'

/** A minimal valid no-auth profile that tests mutate one field at a time. */
export function baseProfileInput(overrides: Record<string, unknown> = {}) {
  return {
    profile_id: 'public',
    api_id: 'example',
    origins: ['https://api.example.com'],
    auth: { type: 'none' },
    permissions: [{ method: 'GET', path: '/works/**', decision: 'auto' }],
    ...overrides,
  }
}

export function parseProfile(overrides: Record<string, unknown> = {}): ExecutionProfile {
  return ExecutionProfile.parse(baseProfileInput(overrides))
}
