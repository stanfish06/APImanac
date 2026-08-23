/**
 * Tracked-secret detection. Catalog YAML names an abstract credential and its
 * components; a value, a variable name, a credential path, or a local account
 * identifier in tracked text is a contract violation.
 *
 * Findings carry the file and the field path and never the matched text.
 */

export type SecretFindingKind =
  | 'credential_value'
  | 'environment_variable_name'
  | 'credential_file_path'
  | 'local_account_identifier'

export interface SecretFinding {
  readonly file: string
  readonly field: string
  readonly kind: SecretFindingKind
  readonly detector: string
}

interface Detector {
  readonly name: string
  readonly kind: SecretFindingKind
  readonly pattern: RegExp
}

const DETECTORS: readonly Detector[] = [
  {
    name: 'github-pat',
    kind: 'credential_value',
    pattern: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{16,}\b/,
  },
  {
    name: 'github-fine-grained-pat',
    kind: 'credential_value',
    pattern: /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  },
  { name: 'openai-key', kind: 'credential_value', pattern: /\bsk-[A-Za-z0-9]{20,}\b/ },
  { name: 'slack-token', kind: 'credential_value', pattern: /\bxox[abprs]-[A-Za-z0-9-]{10,}\b/ },
  { name: 'aws-access-key-id', kind: 'credential_value', pattern: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/ },
  { name: 'google-api-key', kind: 'credential_value', pattern: /\bAIza[0-9A-Za-z_-]{35}\b/ },
  {
    name: 'jwt',
    kind: 'credential_value',
    pattern: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/,
  },
  {
    name: 'authorization-literal',
    kind: 'credential_value',
    pattern: /\b(?:Bearer|Basic|Token)\s+[A-Za-z0-9+/=_.~-]{16,}/,
  },
  {
    name: 'private-key-block',
    kind: 'credential_value',
    pattern: /-----BEGIN[A-Z ]*PRIVATE KEY-----/,
  },
  {
    name: 'credential-env-var',
    kind: 'environment_variable_name',
    pattern:
      /\b[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*_(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|CREDENTIALS|APIKEY|AUTH)\b/,
  },
  {
    name: 'credential-env-var-prefixed',
    kind: 'environment_variable_name',
    pattern: /\b(?:TOKEN|SECRET|PASSWORD|API_KEY|APIKEY|ACCESS_KEY)_[A-Z][A-Z0-9_]*\b/,
  },
  {
    name: 'env-interpolation',
    kind: 'environment_variable_name',
    pattern: /\$\{?[A-Z][A-Z0-9_]{2,}\}?/,
  },
  {
    name: 'credential-file-path',
    kind: 'credential_file_path',
    pattern:
      /(?:^|[\s"'=:])(?:~|\$HOME)?\/?(?:[\w.-]+\/)*(?:\.netrc|\.npmrc|\.pgpass|id_rsa|id_ed25519|credentials|secrets?)(?:\.[\w]+)?(?:$|[\s"'])/i,
  },
  {
    name: 'ssh-directory',
    kind: 'credential_file_path',
    pattern: /(?:^|[\s"'=:/])\.(?:ssh|gnupg|aws|config\/gh)\//,
  },
  {
    name: 'home-directory-path',
    kind: 'local_account_identifier',
    pattern: /(?:^|[\s"'=:])(?:\/home\/[\w.-]+|\/Users\/[\w.-]+|~\/)/,
  },
  { name: 'xdg-interpolation', kind: 'local_account_identifier', pattern: /\$\{?XDG_[A-Z_]+\}?/ },
  {
    name: 'user-interpolation',
    kind: 'local_account_identifier',
    pattern: /\$\{?(?:USER|USERNAME|LOGNAME)\}?/,
  },
]

/** Field paths whose values are URLs; a `secrets`-shaped path segment there is not a finding. */
const URL_FIELDS =
  /(?:^|\.)(?:homepage|documentation|url|origins(?:\[\d+\])?)$|forward_credentials\[\d+\]\.(?:from|to)$/

function scanText(text: string, file: string, field: string, findings: SecretFinding[]): void {
  const urlLike = URL_FIELDS.test(field) || /^https?:\/\//.test(text)
  for (const detector of DETECTORS) {
    if (urlLike && detector.kind !== 'credential_value') continue
    if (detector.pattern.test(text)) {
      findings.push({ file, field, kind: detector.kind, detector: detector.name })
    }
  }
}

function walk(value: unknown, file: string, field: string, findings: SecretFinding[]): void {
  if (typeof value === 'string') {
    scanText(value, file, field, findings)
    return
  }
  if (Array.isArray(value)) {
    for (const [index, item] of value.entries()) {
      walk(item, file, `${field}[${index}]`, findings)
    }
    return
  }
  if (value !== null && typeof value === 'object') {
    for (const [key, item] of Object.entries(value as Record<string, unknown>)) {
      scanText(key, file, field ? `${field}.${key}` : key, findings)
      walk(item, file, field ? `${field}.${key}` : key, findings)
    }
  }
}

/** Scan a parsed tracked document. The returned findings never carry the value. */
export function detectTrackedSecrets(file: string, document: unknown): SecretFinding[] {
  const findings: SecretFinding[] = []
  walk(document, file, '', findings)
  return findings
}

export function describeSecretFinding(finding: SecretFinding): string {
  const what: Record<SecretFindingKind, string> = {
    credential_value: 'a credential value',
    environment_variable_name: 'an environment-variable name',
    credential_file_path: 'a path to a credential',
    local_account_identifier: 'a local account identifier',
  }
  return `${finding.file}: field \`${finding.field || '<root>'}\` looks like ${what[finding.kind]} (${finding.detector}); tracked YAML names an abstract credential and its components instead`
}
