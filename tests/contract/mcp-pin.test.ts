import { describe, expect, test } from 'bun:test'
import {
  LATEST_PROTOCOL_VERSION,
  SUPPORTED_PROTOCOL_VERSIONS,
} from '@modelcontextprotocol/sdk/types.js'
import { MCP_PIN } from '../../src/mcp-pin'
import packageJson from '../../package.json'

describe('the MCP surface is pinned', () => {
  test('the recorded SDK version is the installed one', () => {
    expect(packageJson.dependencies['@modelcontextprotocol/sdk']).toBe(MCP_PIN.sdkVersion)
  })

  test('the recorded protocol revision is what the pinned SDK advertises', () => {
    expect(MCP_PIN.protocolRevision).toBe(LATEST_PROTOCOL_VERSION)
    expect(SUPPORTED_PROTOCOL_VERSIONS).toContain(MCP_PIN.protocolRevision)
  })

  test('the pin is not below the revision that introduced client elicitation', () => {
    expect(MCP_PIN.protocolRevision >= MCP_PIN.minimumElicitationRevision).toBe(true)
    expect(MCP_PIN.minimumElicitationRevision).toBe('2025-06-18')
  })

  test('the pin is an exact version, not a range', () => {
    expect(MCP_PIN.sdkVersion).toMatch(/^\d+\.\d+\.\d+$/)
  })
})
