import { contractHash } from './canonical'
import { buildIdentityIndex } from './identity'
import type { CatalogIssue, CatalogSnapshot } from './load'
import { countLedger } from '../schema/report'
import { SUPPORTED_SCHEMA_VERSION } from '../schema/manifest'
import { canonicalHash } from './canonical'
import { detectTrackedSecrets, describeSecretFinding } from './secrets'

/**
 * Catalog integrity. Every check runs and every finding is reported — never
 * only the first — and nothing here opens a network connection.
 */

export interface ValidationReport {
  readonly ok: boolean
  readonly findings: CatalogIssue[]
}

export function validateCatalog(snapshot: CatalogSnapshot): ValidationReport {
  const findings: CatalogIssue[] = [...snapshot.issues]

  const manifest = snapshot.manifest
  if (manifest && manifest.schema_version !== SUPPORTED_SCHEMA_VERSION) {
    findings.push({
      kind: 'unsupported_schema_version',
      file: 'catalog/manifest.yaml',
      field: 'schema_version',
      message: `catalog declares schema version ${manifest.schema_version}; this build supports ${SUPPORTED_SCHEMA_VERSION}. Run \`apimanac migrate\`.`,
    })
  }

  const declaredSources = new Set<string>(manifest?.sources.map((source) => source.id) ?? [])
  declaredSources.add('manual')

  findings.push(...buildIdentityIndex(snapshot.records).issues)

  for (const source of manifest?.sources ?? []) {
    const declared = snapshot.sourceManifests.get(source.id)
    if (!declared) continue
    const expected = `catalog/sources/${source.id}/manifest.yaml`
    if (source.manifest !== expected) {
      findings.push({
        kind: 'filename_mismatch',
        file: 'catalog/manifest.yaml',
        field: 'sources',
        message: `source \`${source.id}\` declares its manifest at ${source.manifest}, but it is at ${expected}`,
      })
    }
    if (!snapshot.ledgers.has(source.id)) {
      findings.push({
        kind: 'ledger_mismatch',
        file: declared.file,
        message: `source \`${source.id}\` has a manifest but no outcomes.yaml`,
      })
    }
  }

  for (const entry of snapshot.records.values()) {
    for (const [field, provenance] of Object.entries(entry.value.provenance)) {
      if (!declaredSources.has(provenance.source)) {
        findings.push({
          kind: 'unknown_source',
          file: entry.file,
          field: `provenance.${field}`,
          message: `names source \`${provenance.source}\`, which the root manifest does not declare`,
        })
      }
    }
    for (const source of entry.value.sources) {
      if (!declaredSources.has(source)) {
        findings.push({
          kind: 'unknown_source',
          file: entry.file,
          field: 'sources',
          message: `names source \`${source}\`, which the root manifest does not declare`,
        })
      }
    }
    for (const profileId of entry.value.profiles) {
      if (!snapshot.profiles.has(`${entry.value.id}/${profileId}`)) {
        findings.push({
          kind: 'dangling_profile_link',
          file: entry.file,
          field: 'profiles',
          message: `links execution profile \`${profileId}\`, which has no file at catalog/execution/${entry.value.id}/${profileId}.yaml`,
        })
      }
    }
  }

  for (const entry of snapshot.profiles.values()) {
    const profile = entry.value
    if (!snapshot.records.has(profile.api_id)) {
      findings.push({
        kind: 'missing_api_reference',
        file: entry.file,
        field: 'api_id',
        message: `declares api \`${profile.api_id}\`, which has no metadata record`,
      })
    }
    const sources = new Set(
      Object.values(profile.provenance).filter((source) => source && source !== 'manual'),
    )
    for (const source of sources) {
      if (!declaredSources.has(source)) {
        findings.push({
          kind: 'unknown_source',
          file: entry.file,
          field: 'provenance',
          message: `names source \`${source}\`, which the root manifest does not declare`,
        })
      }
    }
    const evidence = profile.verification.evidence
    if (profile.verification.state === 'verified' && evidence) {
      const computed = contractHash(profile)
      if (evidence.contract_hash !== computed) {
        findings.push({
          kind: 'evidence_mismatch',
          file: entry.file,
          field: 'verification.evidence.contract_hash',
          message: `evidence records ${evidence.contract_hash} but the profile hashes to ${computed}; re-run \`apimanac verify\``,
        })
      }
    }
  }

  for (const [sourceId, manifestEntry] of snapshot.sourceManifests) {
    const ledger = snapshot.ledgers.get(sourceId)
    if (!ledger) {
      findings.push({
        kind: 'ledger_mismatch',
        file: manifestEntry.file,
        message: `source \`${sourceId}\` has a manifest but no outcomes.yaml`,
      })
      continue
    }
    const counts = countLedger(ledger.value)
    const declared = manifestEntry.value.counts
    if (
      counts.total !== declared.total ||
      counts.imported !== declared.imported ||
      counts.aliased !== declared.aliased ||
      counts.rejected !== declared.rejected
    ) {
      findings.push({
        kind: 'ledger_mismatch',
        file: manifestEntry.file,
        field: 'counts',
        message: `manifest records ${JSON.stringify(declared)} but the ledger holds ${JSON.stringify(counts)}`,
      })
    }
    const ledgerHash = canonicalHash(JSON.parse(JSON.stringify(ledger.value)) as unknown)
    if (manifestEntry.value.ledger_hash !== ledgerHash) {
      findings.push({
        kind: 'ledger_mismatch',
        file: manifestEntry.file,
        field: 'ledger_hash',
        message: `manifest records ${manifestEntry.value.ledger_hash} but the ledger hashes to ${ledgerHash}`,
      })
    }
    for (const entry of ledger.value.entries) {
      if (entry.outcome === 'rejected') continue
      if (!snapshot.records.has(entry.api_id)) {
        findings.push({
          kind: 'missing_api_reference',
          file: ledger.file,
          field: entry.source_entry_id,
          message: `records outcome \`${entry.outcome}\` for api \`${entry.api_id}\`, which has no metadata record`,
        })
      }
    }
  }

  const documents: [string, unknown][] = [
    ...[...snapshot.records.values()].map(
      (entry) => [entry.file, entry.value as unknown] as [string, unknown],
    ),
    ...[...snapshot.profiles.values()].map(
      (entry) => [entry.file, entry.value as unknown] as [string, unknown],
    ),
  ]
  for (const [file, document] of documents) {
    for (const finding of detectTrackedSecrets(file, document)) {
      findings.push({
        kind: 'tracked_secret',
        file: finding.file,
        field: finding.field,
        message: describeSecretFinding(finding),
      })
    }
  }

  findings.sort((a, b) =>
    a.file === b.file ? ((a.field ?? '') < (b.field ?? '') ? -1 : 1) : a.file < b.file ? -1 : 1,
  )

  return { ok: findings.length === 0, findings }
}

export function formatFinding(finding: CatalogIssue): string {
  const location = finding.field ? `${finding.file}:${finding.field}` : finding.file
  return `${finding.kind}: ${location}: ${finding.message}`
}
