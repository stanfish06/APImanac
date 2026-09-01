import { writeFileSync } from 'node:fs'
import { afterAll, beforeAll, describe, expect, test } from 'bun:test'
import { Client } from '@modelcontextprotocol/sdk/client/index.js'
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js'
import { ElicitRequestSchema } from '@modelcontextprotocol/sdk/types.js'
import { stringify } from 'yaml'
import { MCP_PIN } from '../../src/mcp-pin'
import {
  CallApiInput,
  TOOL_NAMES,
  buildServer,
  callApiInputIsApprovalFree,
  elicitationApproved,
  executionInputsAreApprovalFree,
} from '../../src/mcp'
import { resolveDeno } from '../../src/execute/sandbox'
import { MOCK_SECRET } from '../fixtures/http/mock-server'
import {
  executionFixture,
  fingerprintOf,
  readProfile,
  type ExecutionFixture,
} from '../helpers/execution'
import { writeWorkflow } from '../helpers/workflow'

let fixture: ExecutionFixture

beforeAll(async () => {
  fixture = await executionFixture()
})

afterAll(() => fixture.dispose())

type Action = 'accept' | 'decline' | 'cancel'

/** What a client returns on accept. `undefined` means an accept with no content. */
type AcceptContent = Record<string, unknown> | undefined

interface Session {
  readonly client: Client
  readonly elicitations: string[]
  close(): Promise<void>
}

/** Connect a client with or without the elicitation capability negotiated. */
async function connect(
  options: { elicitation?: Action; content?: AcceptContent } = {},
): Promise<Session> {
  const elicitations: string[] = []
  const client = new Client(
    { name: 'test-client', version: '0.0.0' },
    { capabilities: options.elicitation ? { elicitation: {} } : {} },
  )
  if (options.elicitation) {
    client.setRequestHandler(ElicitRequestSchema, (request) => {
      elicitations.push(request.params.message)
      if (options.elicitation !== 'accept') return { action: options.elicitation }
      return 'content' in options
        ? { action: 'accept', content: options.content }
        : { action: 'accept', content: { send: true } }
    })
  }
  const server = buildServer(fixture.reopen(), {
    grantsPath: fixture.grantsPath,
    healthPath: fixture.healthPath,
    cacheDir: fixture.cacheDir,
    storePath: `${fixture.repo.root}/catalog.db`,
  })
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair()
  await Promise.all([server.connect(serverTransport), client.connect(clientTransport)])
  return {
    client,
    elicitations,
    close: async () => {
      await client.close()
      await server.close()
    },
  }
}

interface ToolPayload {
  outcome?: string
  message?: string
  status?: number
  body?: string
  results?: { id: string }[]
  applied_limit?: number
  requested_limit?: number
  more_matches?: boolean
  total_matches?: number
  profiles?: { profile_id: string; eligible: boolean; reason?: string }[]
  candidates?: string[]
  missing_components?: string[]
  preview?: string
  remote_content?: boolean
  error?: string
  id?: string
  matched_alias?: string
  [key: string]: unknown
}

async function callTool(session: Session, name: string, args: Record<string, unknown>) {
  const result = (await session.client.callTool({ name, arguments: args })) as {
    content: { type: string; text: string }[]
    isError?: boolean
  }
  const text = result.content[0]?.text ?? '{}'
  return { payload: JSON.parse(text) as ToolPayload, isError: result.isError === true, text }
}

/** The MCP server resolves through the real providers, so bind real env vars. */
function grantFor(profileId: string, values: Record<string, string>) {
  const profile = readProfile(fixture.repo, profileId)
  const variables = Object.fromEntries(
    Object.keys(values).map((name) => [name, `APIMANAC_MCP_TEST_${name.toUpperCase()}`]),
  )
  for (const [name, variable] of Object.entries(variables)) {
    process.env[variable] = values[name]
  }
  writeFileSync(
    fixture.grantsPath,
    stringify({
      version: 1,
      grants: [
        {
          credential_id: profile.auth.credential_id,
          api_id: 'mock',
          profile_id: profileId,
          origins: profile.origins,
          authority_fingerprint: fingerprintOf(fixture.repo, profileId),
          accounts: [
            {
              name: 'primary',
              components: Object.fromEntries(
                Object.entries(variables).map(([name, variable]) => [
                  name,
                  { provider: 'env', variable },
                ]),
              ),
            },
          ],
        },
      ],
    }),
    { mode: 0o600 },
  )
}

describe('the server speaks stdio and exposes exactly five tools', () => {
  test('exactly the five declared tools are advertised', async () => {
    const session = await connect()
    try {
      const listed = await session.client.listTools()
      expect(listed.tools.map((tool) => tool.name).sort()).toEqual([...TOOL_NAMES].sort())
      expect([...TOOL_NAMES]).toEqual([
        'search_apis',
        'get_api',
        'call_api',
        'run_workflow',
        'run_script',
      ])
    } finally {
      await session.close()
    }
  })

  test('no execution tool schema carries an approval, token or consent field', async () => {
    const session = await connect()
    try {
      const listed = await session.client.listTools()
      for (const name of ['call_api', 'run_workflow', 'run_script']) {
        const tool = listed.tools.find((entry) => entry.name === name)
        const properties = Object.keys(
          (tool?.inputSchema as { properties?: Record<string, unknown> }).properties ?? {},
        )
        for (const property of properties) {
          expect(`${name}.${property}:${/token|approv|consent|confirm/i.test(property)}`).toBe(
            `${name}.${property}:false`,
          )
        }
      }
    } finally {
      await session.close()
    }
  })

  test('the approval-free guard covers every execution input', () => {
    expect(callApiInputIsApprovalFree()).toBe(true)
    expect(executionInputsAreApprovalFree()).toBe(true)
    expect(Object.keys(CallApiInput)).not.toContain('approved')
  })

  test('the server module opens no network listener', async () => {
    const source = await Bun.file(
      Bun.fileURLToPath(new URL('../../src/mcp.ts', import.meta.url)),
    ).text()
    expect(source).not.toContain('createServer')
    expect(source).not.toContain('.listen(')
    expect(source).toContain('StdioServerTransport')
  })
})

describe('search_apis returns compact labeled summaries', () => {
  test('a result carries no endpoint list, specification body, or credential material', async () => {
    const session = await connect()
    try {
      const { payload, text } = await callTool(session, 'search_apis', { query: 'mock' })
      expect(payload.results?.[0]?.id).toBe('mock')
      expect(text).not.toContain(fixture.mock.origin)
      expect(text).not.toContain('/ok')
      expect(text).not.toContain('permissions')
      expect(text).not.toContain(MOCK_SECRET)
    } finally {
      await session.close()
    }
  })

  test('a limit above the server bound is clamped and the applied limit reported', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'search_apis', { query: 'mock', limit: 999 })
      expect(payload.applied_limit).toBe(25)
      expect(payload.requested_limit).toBe(999)
    } finally {
      await session.close()
    }
  })

  test('a limit smaller than the match count reports that more matches exist', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'search_apis', { query: '', limit: 1 })
      expect(payload.results).toHaveLength(1)
      expect(typeof payload.total_matches).toBe('number')
    } finally {
      await session.close()
    }
  })

  test('an out-of-vocabulary filter is rejected by the advertised schema', async () => {
    const session = await connect()
    try {
      // The tool schema is generated from the same closed vocabulary the server
      // validates against, so the value never reaches the handler.
      await expect(
        callTool(session, 'search_apis', { query: 'mock', lifecycle: 'zombie' }),
      ).rejects.toThrow()
    } finally {
      await session.close()
    }
  })
})

describe('get_api returns bounded inspection detail', () => {
  test('an alias resolves and the alias used is reported', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'get_api', { api: 'mock-api' })
      expect(payload.id).toBe('mock')
      expect(payload.matched_alias).toBe('mock-api')
    } finally {
      await session.close()
    }
  })

  test('an unknown id is a typed not-found with no partial record', async () => {
    const session = await connect()
    try {
      const { payload, isError } = await callTool(session, 'get_api', { api: 'nope' })
      expect(isError).toBe(true)
      expect(payload.error).toBe('not_found')
      expect(payload.id).toBeUndefined()
    } finally {
      await session.close()
    }
  })

  test('a profile selector scopes the result', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'get_api', { api: 'mock', profile: 'public' })
      expect(payload.profiles).toHaveLength(1)
      expect(payload.profiles?.[0]?.profile_id).toBe('public')
    } finally {
      await session.close()
    }
  })

  test('the result reports permission decisions and the authority fingerprint', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'get_api', { api: 'mock', profile: 'public' })
      const profile = payload.profiles?.[0] as unknown as {
        operations: { decision: string }[]
        authority_fingerprint: string
        contract_hash: string
      }
      expect(profile.operations.some((operation) => operation.decision === 'deny')).toBe(true)
      expect(profile.authority_fingerprint).toMatch(/^v1:sha256:/)
      expect(profile.contract_hash).toMatch(/^v1:sha256:/)
    } finally {
      await session.close()
    }
  })
})

describe('call_api distinguishes every outcome', () => {
  test('an auto operation succeeds on a client without elicitation', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'GET',
        path: '/ok',
      })
      expect(payload.outcome).toBe('success')
      expect(payload.status).toBe(200)
      expect(payload.remote_content).toBe(true)
    } finally {
      await session.close()
    }
  })

  test('a denied operation is a denied outcome and sends no request', async () => {
    const session = await connect()
    const before = fixture.mock.requests.length
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'DELETE',
        path: '/ok',
      })
      expect(payload.outcome).toBe('denied')
      expect(fixture.mock.requests.length).toBe(before)
    } finally {
      await session.close()
    }
  })

  test('a missing grant names the credential id and required components', async () => {
    writeFileSync(fixture.grantsPath, stringify({ version: 1, grants: [] }), { mode: 0o600 })
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'keyed',
        method: 'GET',
        path: '/auth',
      })
      expect(payload.outcome).toBe('missing_grant')
      expect(payload.message).toContain('mock-token')
      expect(payload.missing_components).toEqual(['token'])
    } finally {
      await session.close()
    }
  })

  test('an unsupported auth type is refused before any credential resolution', async () => {
    fixture.writeProfile('mcpoauth', {
      auth: { type: 'oauth2', credential_id: 'mock-oauth', components: [{ name: 'access_token' }] },
    })
    fixture.repo.commit('add mcpoauth profile')
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'mcpoauth',
        method: 'GET',
        path: '/ok',
      })
      expect(payload.outcome).toBe('unsupported_auth')
    } finally {
      await session.close()
    }
  })

  test('a 5xx is reported as bounded remote content, not an APImanac failure', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'GET',
        path: '/status/503',
      })
      expect(payload.outcome).toBe('remote_response')
      expect(payload.status).toBe(503)
      expect(payload.remote_content).toBe(true)
    } finally {
      await session.close()
    }
  })

  test('an inline overflow reports the bound rather than a truncated body', async () => {
    fixture.writeProfile('mcpsmall', {
      response: { inline_max_bytes: 1024, inline_max_compressed_bytes: 1024 },
      permissions: [{ method: 'GET', path: '/large', decision: 'auto' }],
    })
    fixture.repo.commit('add mcpsmall profile')
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'mcpsmall',
        method: 'GET',
        path: '/large',
      })
      expect(payload.outcome).toBe('policy_failure')
      expect(payload.message).toMatch(/bound/)
      expect(payload.body).toBeUndefined()
    } finally {
      await session.close()
    }
  })

  test('a file response returns the path, media type, size and hash', async () => {
    fixture.writeProfile('mcpfile', {
      permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
    })
    fixture.repo.commit('add mcpfile profile')
    const session = await connect()
    try {
      const { payload, text } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'mcpfile',
        method: 'GET',
        path: '/ok',
        response_mode: 'file',
      })
      expect(payload.outcome).toBe('success')
      const file = payload.file as { path: string; hash: string; media_type: string }
      expect(file.path).toBeTruthy()
      expect(file.hash).toMatch(/^v1:sha256:/)
      expect(text).not.toContain(MOCK_SECRET)
    } finally {
      await session.close()
    }
  })

  test('several eligible profiles return structured candidates and send no request', async () => {
    const before = fixture.mock.requests.length
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        method: 'GET',
        path: '/ok',
      })
      expect(payload.outcome).toBe('ambiguous_profile')
      expect((payload.candidates ?? []).length).toBeGreaterThan(1)
      expect(fixture.mock.requests.length).toBe(before)
    } finally {
      await session.close()
    }
  })

  test('a result never carries a token or resumable approval handle', async () => {
    const session = await connect()
    try {
      const { text } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'GET',
        path: '/ok',
      })
      for (const forbidden of ['nonce', 'binding', 'approval', 'token', 'handle']) {
        expect(`${forbidden}:${text.toLowerCase().includes(forbidden)}`).toBe(`${forbidden}:false`)
      }
    } finally {
      await session.close()
    }
  })
})

describe('confirmation happens by elicitation inside the invocation', () => {
  test('a client without elicitation is refused and directed to interactive apimanac call', async () => {
    const before = fixture.mock.requests.length
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'POST',
        path: '/echo',
        body_json: { a: 1 },
      })
      expect(payload.outcome).toBe('confirmation_required')
      expect(payload.message).toContain('apimanac call')
      expect(fixture.mock.requests.length).toBe(before)
    } finally {
      await session.close()
    }
  })

  test('an accept executes within the same invocation, needing no second call', async () => {
    const session = await connect({ elicitation: 'accept' })
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'POST',
        path: '/echo',
        body_json: { a: 1 },
      })
      expect(session.elicitations).toHaveLength(1)
      expect(session.elicitations[0]).toContain('POST')
      expect(payload.outcome).toBe('success')
      expect(payload.body).toContain('"method":"POST"')
    } finally {
      await session.close()
    }
  })

  test('a decline mints nothing and sends no request', async () => {
    const before = fixture.mock.requests.length
    const session = await connect({ elicitation: 'decline' })
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'POST',
        path: '/echo',
        body_json: { a: 1 },
      })
      expect(payload.outcome).toBe('confirmation_declined')
      expect(fixture.mock.requests.length).toBe(before)
    } finally {
      await session.close()
    }
  })

  test('a cancel mints nothing and sends no request', async () => {
    const before = fixture.mock.requests.length
    const session = await connect({ elicitation: 'cancel' })
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'POST',
        path: '/echo',
        body_json: { a: 1 },
      })
      expect(payload.outcome).toBe('confirmation_declined')
      expect(fixture.mock.requests.length).toBe(before)
    } finally {
      await session.close()
    }
  })

  test.each([
    ['no content at all', undefined],
    ['content with no send field', {}],
    ['send: false', { send: false }],
    ['send: null', { send: null }],
    ['send as the string "true"', { send: 'true' }],
    ['send: 1', { send: 1 }],
  ])('an accept carrying %s sends nothing', async (_label, content) => {
    const before = fixture.mock.requests.length
    const session = await connect({ elicitation: 'accept', content })
    try {
      // Either the SDK rejects the malformed response against the declared
      // schema, or the channel declines it. Both must send no request.
      let outcome: string | undefined
      try {
        outcome = (
          await callTool(session, 'call_api', {
            api: 'mock',
            profile: 'public',
            method: 'POST',
            path: '/echo',
            body_json: { a: 1 },
          })
        ).payload.outcome
      } catch {
        outcome = 'protocol_error'
      }
      expect(session.elicitations).toHaveLength(1)
      expect(outcome).not.toBe('success')
      expect(fixture.mock.requests.length).toBe(before)
    } finally {
      await session.close()
    }
  })

  test.each([
    ['a decline', { action: 'decline' }],
    ['a cancel', { action: 'cancel' }],
    ['an accept with no content', { action: 'accept' }],
    ['an accept with no send field', { action: 'accept', content: {} }],
    ['an accept with send: false', { action: 'accept', content: { send: false } }],
    ['an accept with send: null', { action: 'accept', content: { send: null } }],
    ['an accept with send: "true"', { action: 'accept', content: { send: 'true' } }],
    ['an accept with send: 1', { action: 'accept', content: { send: 1 } }],
  ])('the channel predicate treats %s as no consent', (_label, response) => {
    expect(elicitationApproved(response)).toBe(false)
  })

  test('the channel predicate approves only a literal true', () => {
    expect(elicitationApproved({ action: 'accept', content: { send: true } })).toBe(true)
  })

  test('a model-supplied approval field is ignored and the operation still elicits', async () => {
    const session = await connect({ elicitation: 'accept' })
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'POST',
        path: '/echo',
        body_json: { a: 1 },
        approved: true,
        approval_token: 'a'.repeat(64),
      })
      expect(session.elicitations).toHaveLength(1)
      expect(payload.outcome).toBe('success')
    } finally {
      await session.close()
    }
  })

  test('an auto operation on a client without elicitation still executes', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'GET',
        path: '/ok',
      })
      expect(payload.outcome).toBe('success')
      expect(session.elicitations).toHaveLength(0)
    } finally {
      await session.close()
    }
  })

  test('the pinned protocol revision is what the result reports', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'GET',
        path: '/ok',
      })
      expect(payload.protocol_revision).toBe(MCP_PIN.protocolRevision)
    } finally {
      await session.close()
    }
  })
})

describe('a long-lived server sees a reviewer commit without restarting', () => {
  test('a profile committed after the server started becomes callable', async () => {
    // The server captures a root at build time; if it also captured HEAD, a
    // commit made now would not take effect until restart.
    fixture.writeProfile('latecommit', {
      permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
    })
    const session = await connect()
    try {
      const before = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'latecommit',
        method: 'GET',
        path: '/ok',
      })
      expect(before.payload.outcome).toBe('ineligible')

      // A reviewer commits while the same session stays open.
      fixture.repo.commit('commit the late profile')

      const after = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'latecommit',
        method: 'GET',
        path: '/ok',
      })
      expect(after.payload.outcome).toBe('success')
    } finally {
      await session.close()
    }
  })

  test('an edit after that commit refuses again on the same session', async () => {
    fixture.writeProfile('reedited', {
      permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
    })
    fixture.repo.commit('commit the profile')
    const session = await connect()
    try {
      expect(
        (
          await callTool(session, 'call_api', {
            api: 'mock',
            profile: 'reedited',
            method: 'GET',
            path: '/ok',
          })
        ).payload.outcome,
      ).toBe('success')

      fixture.writeProfile('reedited', {
        description: 'edited after the call',
        permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
      })
      const after = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'reedited',
        method: 'GET',
        path: '/ok',
      })
      expect(after.payload.outcome).toBe('ineligible')
      expect(after.payload.message).toContain('differs from the committed snapshot')
    } finally {
      await session.close()
    }
  })
})

describe('no MCP result carries credential material', () => {
  test('an authenticated success leaks no secret or authenticated URL', async () => {
    grantFor('keyed', { token: MOCK_SECRET })
    const session = await connect()
    try {
      const { payload, text } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'keyed',
        method: 'GET',
        path: '/auth',
      })
      expect(payload.outcome).toBe('success')
      expect(text).not.toContain(MOCK_SECRET)
      expect(text).not.toContain(encodeURIComponent(MOCK_SECRET))
      expect(text).not.toContain('Authorization')
    } finally {
      await session.close()
    }
  })

  test('an authenticated failure leaks no secret', async () => {
    fixture.writeProfile('mcpdead', {
      origins: ['http://127.0.0.1:1'],
      auth: {
        type: 'bearer',
        credential_id: 'mock-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      permissions: [{ method: 'GET', path: '/ok', decision: 'auto' }],
    })
    fixture.repo.commit('add mcpdead profile')
    grantFor('mcpdead', { token: MOCK_SECRET })
    const session = await connect()
    try {
      const { payload, text } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'mcpdead',
        method: 'GET',
        path: '/ok',
      })
      expect(payload.outcome).toBe('network_failure')
      expect(text).not.toContain(MOCK_SECRET)
    } finally {
      await session.close()
    }
  })

  test('a credential echo contains and returns no body', async () => {
    fixture.writeProfile('mcpecho', {
      auth: {
        type: 'bearer',
        credential_id: 'mock-token',
        components: [{ name: 'token' }],
        placements: [{ kind: 'header', header: 'Authorization', template: 'Bearer {token}' }],
      },
      permissions: [{ method: 'GET', path: '/echo-credential', decision: 'auto' }],
    })
    fixture.repo.commit('add mcpecho profile')
    grantFor('mcpecho', { token: MOCK_SECRET })
    const session = await connect()
    try {
      const { payload, text } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'mcpecho',
        method: 'GET',
        path: '/echo-credential',
      })
      expect(payload.outcome).toBe('credential_echo_detected')
      expect(payload.body).toBeUndefined()
      expect(text).not.toContain(MOCK_SECRET)
    } finally {
      await session.close()
    }
  })

  test('remote text that reads as instructions is labeled remote content', async () => {
    const session = await connect()
    try {
      const { payload } = await callTool(session, 'call_api', {
        api: 'mock',
        profile: 'public',
        method: 'GET',
        path: '/instructions',
      })
      expect(payload.remote_content).toBe(true)
      expect(payload.body).toContain('ignore previous instructions')
      expect(payload.message).not.toContain('ignore previous instructions')
    } finally {
      await session.close()
    }
  })
})

describe('workflows run over MCP', () => {
  test('get_api lists workflows without the script body', async () => {
    writeWorkflow(fixture.repo, {
      apiId: 'mock',
      workflowId: 'mcp-list',
      bindings: ['mock/public'],
      script: 'export default async function run() { return 1 }\n',
      description: 'Listed by get_api.',
    })
    fixture.repo.commit('committed mcp-list workflow')
    const session = await connect()
    try {
      const { payload, text } = await callTool(session, 'get_api', { api: 'mock' })
      const workflows = payload.workflows as
        | { workflow_id: string; runnable: boolean }[]
        | undefined
      expect(workflows?.some((workflow) => workflow.workflow_id === 'mcp-list')).toBe(true)
      expect(text).not.toContain('export default')
    } finally {
      await session.close()
    }
  })

  test('run_workflow executes through elicitation-negotiated policy', async () => {
    if (!resolveDeno().ok) return
    writeWorkflow(fixture.repo, {
      apiId: 'mock',
      workflowId: 'mcp-run',
      bindings: ['mock/public'],
      script: `export default async function run({ api }) {
        const r = await api.call('mock/public', { method: 'GET', path: '/ok' })
        return { status: r.status }
      }\n`,
    })
    fixture.repo.commit('committed mcp-run workflow')
    const session = await connect({ elicitation: 'accept' })
    try {
      const { payload, isError } = await callTool(session, 'run_workflow', {
        api: 'mock',
        workflow: 'mcp-run',
      })
      expect(isError).toBe(false)
      expect((payload.result as { status: number }).status).toBe(200)
    } finally {
      await session.close()
    }
  }, 30000)

  test('run_script without elicitation is refused', async () => {
    const session = await connect()
    try {
      const { payload, isError } = await callTool(session, 'run_script', {
        source: 'export default async function run() { return 1 }',
        bindings: ['mock/public'],
      })
      expect(isError).toBe(true)
      expect(payload.kind).toBe('approval_required')
    } finally {
      await session.close()
    }
  })
})
