/**
 * Pinned MCP surface. `sdkVersion` must equal the `@modelcontextprotocol/sdk`
 * version in package.json, and `protocolRevision` the revision that SDK
 * advertises as latest. Client fixtures for elicitation are written against
 * `protocolRevision`.
 */
export const MCP_PIN = {
  sdkVersion: '1.21.0',
  protocolRevision: '2025-06-18',
  /** Revision that introduced client elicitation; the pin may not go below it. */
  minimumElicitationRevision: '2025-06-18',
} as const
