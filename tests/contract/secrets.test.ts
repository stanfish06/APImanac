import { describe, expect, test } from 'bun:test'
import { describeSecretFinding, detectTrackedSecrets } from '../../src/catalog/secrets'

function kinds(document: unknown): string[] {
  return detectTrackedSecrets('catalog/meta/x.yaml', document).map((f) => f.kind)
}

describe('tracked-secret detection', () => {
  test.each([
    ['a GitHub personal access token', { description: `ghp_${'a'.repeat(36)}` }],
    ['an OpenAI-style key', { description: `sk-${'B'.repeat(32)}` }],
    ['an AWS access key id', { description: 'AKIAIOSFODNN7EXAMPLE' }],
    [
      'a JWT',
      { description: 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K' },
    ],
    ['an Authorization literal', { note: 'send Bearer sk1234567890abcdefghij' }],
    ['a private key block', { note: '-----BEGIN RSA PRIVATE KEY-----' }],
  ])('flags %s as a credential value', (_label, document) => {
    expect(kinds(document)).toContain('credential_value')
  })

  test.each([
    ['a token variable', { auth: { env: 'GITHUB_TOKEN' } }],
    ['an api key variable', { auth: { env: 'OPENALEX_API_KEY' } }],
    // biome-ignore lint/suspicious/noTemplateCurlyInString: the literal shape is what the detector must flag
    ['a shell interpolation', { auth: { value: '${MY_SECRET}' } }],
  ])('flags %s as an environment-variable name', (_label, document) => {
    expect(kinds(document)).toContain('environment_variable_name')
  })

  test.each([
    ['a netrc path', { auth: { from: 'read .netrc' } }],
    ['an ssh directory', { auth: { file: 'keys/.ssh/id_ed25519' } }],
    ['a credentials file', { auth: { file: 'aws/credentials' } }],
  ])('flags %s as a credential file path', (_label, document) => {
    expect(kinds(document)).toContain('credential_file_path')
  })

  test.each([
    ['a home directory path', { auth: { file: '/home/alice/key.txt' } }],
    ['a tilde path', { auth: { file: '~/creds' } }],
    ['an XDG interpolation', { auth: { file: '$XDG_DATA_HOME/apimanac' } }],
    ['a user interpolation', { auth: { account: '$USER' } }],
  ])('flags %s as a local account identifier', (_label, document) => {
    expect(kinds(document)).toContain('local_account_identifier')
  })

  test('reports the file and field without echoing the matched value', () => {
    const secret = `ghp_${'z'.repeat(36)}`
    const findings = detectTrackedSecrets('catalog/execution/x/pat.yaml', {
      auth: { placements: [{ template: secret }] },
    })
    expect(findings).toHaveLength(1)
    const finding = findings[0]
    expect(finding?.file).toBe('catalog/execution/x/pat.yaml')
    expect(finding?.field).toBe('auth.placements[0].template')
    const message = describeSecretFinding(finding!)
    expect(message).toContain('auth.placements[0].template')
    expect(message).not.toContain(secret)
    expect(JSON.stringify(finding)).not.toContain(secret)
  })

  test('flags a secret-shaped key name as well as a value', () => {
    expect(kinds({ GITHUB_TOKEN: 'abstract' })).toContain('environment_variable_name')
  })

  test('ordinary catalog text produces no findings', () => {
    expect(
      kinds({
        id: 'openalex',
        name: 'OpenAlex',
        description: 'An open catalog of scholarly works, authors, and institutions.',
        homepage: 'https://openalex.org',
        documentation: 'https://docs.openalex.org/api',
        categories: ['research', 'bibliographic'],
        auth: { type: 'header_key', credential_id: 'openalex-key', components: [{ name: 'key' }] },
      }),
    ).toEqual([])
  })

  test('a documentation URL mentioning authentication is not a finding', () => {
    expect(kinds({ documentation: 'https://docs.example.com/guides/api-keys/secrets' })).toEqual([])
  })
})
