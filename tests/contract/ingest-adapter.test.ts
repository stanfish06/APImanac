import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, expect, test } from 'bun:test'
import { parse, stringify } from 'yaml'
import { canonicalHash, sha256Tagged } from '../../src/catalog/canonical'
import { ApimanacError } from '../../src/errors'
import {
  type AdapterRun,
  buildLedger,
  buildManifest,
  derivedEntryId,
  entryContentHash,
  ledgerHash,
  type SourcePin,
} from '../../src/ingest/adapter'
import { runApisGuru } from '../../src/ingest/apis-guru'
import { runNango } from '../../src/ingest/nango'
import { runPublicApis } from '../../src/ingest/public-apis'
import { MetadataRecord } from '../../src/schema/metadata'
import { REJECTION_DETAIL_MAX } from '../../src/schema/reasons'
import { countLedger, OutcomeLedger } from '../../src/schema/report'
import { fixturePath, loadFixture } from '../helpers/yaml'

function pinFor(source: string): SourcePin {
  const pin = loadFixture('sources', source, 'pin.yaml') as Record<string, string>
  return {
    revision: pin.revision ?? '',
    contentHash: pin.content_hash ?? '',
    retrievedAt: pin.retrieved_at ?? '',
  }
}

/** Keyed by upstream list id: each file is named for its id, `/` as `__`. */
function specMap(): Map<string, unknown> {
  const directory = fixturePath('sources', 'apis-guru', 'specs')
  const specs = new Map<string, unknown>()
  for (const file of [...new Bun.Glob('*.json').scanSync({ cwd: directory })].sort()) {
    specs.set(
      file.replace(/\.json$/, '').replaceAll('__', '/'),
      loadFixture('sources', 'apis-guru', 'specs', file),
    )
  }
  return specs
}

const runs: Record<string, () => AdapterRun> = {
  'public-apis': () =>
    runPublicApis(loadFixture('sources', 'public-apis', 'entries.json'), pinFor('public-apis')),
  nango: () =>
    runNango(
      loadFixture('sources', 'nango', 'providers.yaml'),
      pinFor('nango'),
      loadFixture('sources', 'nango', 'scopes.yaml'),
    ),
  'apis-guru': () =>
    runApisGuru(loadFixture('sources', 'apis-guru', 'list.json'), pinFor('apis-guru'), specMap()),
}

const SOURCE_FILES: [string, string, string][] = [
  ['public-apis', 'entries.json', 'public-apis'],
  ['nango', 'providers.yaml', 'nango'],
  ['apis-guru', 'list.json', 'apis-guru'],
]

describe('adapter contract', () => {
  test('an unexpected upstream shape throws naming the source and writes no candidate', () => {
    const pin: SourcePin = { revision: 'r', contentHash: 'h', retrievedAt: 't' }
    const cases: [string, () => unknown][] = [
      ['public-apis', () => runPublicApis({ entries: 'not an array' }, pin)],
      ['nango', () => runNango([{ display_name: 'Nope' }], pin)],
      ['apis-guru', () => runApisGuru('not a list', pin)],
    ]
    for (const [source, call] of cases) {
      let thrown: unknown
      try {
        call()
      } catch (error) {
        thrown = error
      }
      expect(thrown).toBeInstanceOf(ApimanacError)
      const error = thrown as ApimanacError
      expect(error.kind).toBe('validation_failed')
      expect(error.message).toContain(`source \`${source}\``)
      expect(error.detail.source).toBe(source)
      // The adapter returned nothing, so there is no candidate to write anywhere.
      expect(error.detail.shape).toBeTruthy()
    }
  })

  test('the nango scopes file is validated separately and names the source when it is wrong', () => {
    expect(() =>
      runNango({}, { revision: 'r', contentHash: 'h', retrievedAt: 't' }, ['not', 'a', 'map']),
    ).toThrow(/source `nango`: scopes file/)
  })

  test('metadata and execution candidates are separate outputs', () => {
    const run = runs.nango?.() as AdapterRun
    expect(run.metadata.length).toBeGreaterThan(0)
    expect(run.execution.length).toBeGreaterThan(0)
    for (const candidate of run.metadata) {
      const record = candidate.record as Record<string, unknown>
      expect(record.origins).toBeUndefined()
      expect(record.auth).toBeUndefined()
    }
    for (const candidate of run.execution) {
      const profile = candidate.profile as Record<string, unknown>
      expect(profile.origins).toBeTruthy()
      expect(run.metadata.some((entry) => entry.record === candidate.profile)).toBe(false)
    }
  })

  test('no adapter run produces a verified profile', () => {
    for (const build of Object.values(runs)) {
      for (const candidate of build().execution) {
        const profile = candidate.profile as { verification?: { state?: string } }
        expect(profile.verification?.state).toBe('candidate')
      }
    }
  })

  test('a verified profile is refused before a ledger is built', () => {
    const run = runs.nango?.() as AdapterRun
    const first = run.execution[0]
    expect(first).toBeTruthy()
    const tampered: AdapterRun = {
      ...run,
      execution: [
        {
          ...(first as NonNullable<typeof first>),
          profile: {
            ...((first as NonNullable<typeof first>).profile as object),
            verification: { state: 'verified' },
          },
        },
      ],
    }
    expect(() => buildLedger(tampered)).toThrow(/ingestion produces candidates only/)
  })

  test('running an adapter opens no network connection', () => {
    const dir = Bun.fileURLToPath(new URL('../../src/ingest', import.meta.url))
    const forbidden = [
      'node:http',
      'node:https',
      'node:net',
      'node:tls',
      'node:dgram',
      'node:fs',
      'fetch(',
      'XMLHttpRequest',
      'WebSocket',
      'Bun.connect',
    ]
    const files = readdirSync(dir).filter((name) => name.endsWith('.ts'))
    expect(files.length).toBe(4)
    for (const name of files) {
      const text = readFileSync(join(dir, name), 'utf8')
      for (const token of forbidden) expect(text).not.toContain(token)
    }
  })
})

describe('outcome ledger', () => {
  test('every upstream entry gets exactly one outcome', () => {
    const entries = (
      loadFixture('sources', 'public-apis', 'entries.json') as { entries: unknown[] }
    ).entries
    const ledger = OutcomeLedger.parse(buildLedger(runs['public-apis']?.() as AdapterRun))
    expect(ledger.entries.length).toBe(entries.length)
    expect(new Set(ledger.entries.map((entry) => entry.source_entry_id)).size).toBe(entries.length)

    const providers = loadFixture('sources', 'nango', 'providers.yaml') as Record<string, unknown>
    const nango = OutcomeLedger.parse(buildLedger(runs.nango?.() as AdapterRun))
    expect(nango.entries.map((entry) => entry.source_entry_id).sort()).toEqual(
      Object.keys(providers).sort(),
    )
  })

  test('entries are sorted by source entry id', () => {
    const ledger = buildLedger(runs['apis-guru']?.() as AdapterRun)
    const ids = ledger.entries.map((entry) => entry.source_entry_id)
    expect(ids).toEqual([...ids].sort())
  })

  test('an entry with no usable source id gets a hash-derived id', () => {
    const ledger = buildLedger(runs['public-apis']?.() as AdapterRun)
    const derived = ledger.entries.filter((entry) =>
      entry.source_entry_id.startsWith('public-apis:'),
    )
    expect(derived.length).toBeGreaterThan(0)
    for (const entry of derived) {
      expect(entry.source_entry_id).toMatch(/^public-apis:sha256-[0-9a-f]{16}$/)
      expect(entry.content_hash.replace('v1:sha256:', '').slice(0, 16)).toBe(
        entry.source_entry_id.replace('public-apis:sha256-', ''),
      )
    }
  })

  test('a derived id is stable for the same normalized entry', () => {
    const entry = { API: undefined, Category: 'Development' }
    expect(derivedEntryId('public-apis', entry)).toBe(derivedEntryId('public-apis', { ...entry }))
    expect(entryContentHash(entry)).toBe(entryContentHash({ Category: 'Development' }))
  })

  test('duplicate outcomes fail naming the source and the entry', () => {
    const run: AdapterRun = {
      sourceId: 'nango',
      pin: { revision: 'r', contentHash: 'h', retrievedAt: 't' },
      metadata: [],
      execution: [],
      aliased: [],
      rejections: [
        {
          sourceEntryId: 'stripe',
          contentHash: sha256Tagged('a'),
          reasonCode: 'missing_base_url',
          detail: 'first',
        },
        {
          sourceEntryId: 'stripe',
          contentHash: sha256Tagged('b'),
          reasonCode: 'missing_base_url',
          detail: 'second',
        },
      ],
    }
    expect(() => buildLedger(run)).toThrow(/source `nango` records two outcomes for entry `stripe`/)
  })

  test('a rejection detail longer than the bound is truncated in the written ledger', () => {
    const run: AdapterRun = {
      sourceId: 'nango',
      pin: { revision: 'r', contentHash: 'h', retrievedAt: 't' },
      metadata: [],
      execution: [],
      aliased: [],
      rejections: [
        {
          sourceEntryId: 'stripe',
          contentHash: sha256Tagged('a'),
          reasonCode: 'missing_base_url',
          detail: 'x'.repeat(REJECTION_DETAIL_MAX + 500),
        },
      ],
    }
    const ledger = OutcomeLedger.parse(buildLedger(run))
    const entry = ledger.entries[0]
    expect(entry?.outcome).toBe('rejected')
    if (entry?.outcome === 'rejected') expect(entry.detail.length).toBe(REJECTION_DETAIL_MAX)
  })

  test('an undeclared reason code fails validation naming the code', () => {
    const run: AdapterRun = {
      sourceId: 'nango',
      pin: { revision: 'r', contentHash: 'h', retrievedAt: 't' },
      metadata: [],
      execution: [],
      aliased: [],
      rejections: [
        {
          sourceEntryId: 'stripe',
          contentHash: sha256Tagged('a'),
          reasonCode: 'made_up_code',
          detail: '',
        },
      ],
    }
    const result = OutcomeLedger.safeParse(buildLedger(run))
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues[0]?.message).toContain('made_up_code')
    }
  })
})

describe('source manifest', () => {
  test('counts and ledger hash match the ledger the way validation recomputes them', () => {
    for (const [source, build] of Object.entries(runs)) {
      const run = build()
      const manifest = buildManifest(run, { name: source, license: 'CC0-1.0' })
      const ledger = OutcomeLedger.parse(buildLedger(run))
      expect(manifest.counts).toEqual(countLedger(ledger))
      expect(manifest.ledger_hash).toBe(canonicalHash(JSON.parse(JSON.stringify(ledger))))
      expect(manifest.revision).toBe(run.pin.revision)
      expect(manifest.content_hash).toBe(run.pin.contentHash)
    }
  })

  test('the ledger hash survives a yaml round trip of the tracked file', () => {
    const run = runs['apis-guru']?.() as AdapterRun
    const manifest = buildManifest(run, { name: 'apis-guru', license: 'CC0-1.0' })
    const tracked = OutcomeLedger.parse(parse(stringify(buildLedger(run))))
    expect(ledgerHash(tracked)).toBe(manifest.ledger_hash)
  })

  test('a mismatched count no longer matches the ledger', () => {
    const run = runs.nango?.() as AdapterRun
    const manifest = buildManifest(run, { name: 'nango', license: 'ELv2' })
    const tampered = { ...manifest.counts, imported: manifest.counts.imported + 1 }
    expect(tampered).not.toEqual(countLedger(OutcomeLedger.parse(buildLedger(run))))
  })
})

describe('pinned fixtures', () => {
  test('every fixture parses through its adapter and every candidate is a valid record', () => {
    for (const build of Object.values(runs)) {
      const run = build()
      expect(run.metadata.length).toBeGreaterThan(0)
      for (const candidate of run.metadata) MetadataRecord.parse(candidate.record)
      expect(OutcomeLedger.parse(buildLedger(run)).entries.length).toBeGreaterThan(0)
    }
  })

  test('each pin file parses and its content hash matches the captured payload', () => {
    for (const [dir, file, source] of SOURCE_FILES) {
      const pin = loadFixture('sources', dir, 'pin.yaml') as Record<string, string>
      expect(pin.revision).toBeTruthy()
      expect(pin.retrieved_at).toBeTruthy()
      expect(pin.source_url).toMatch(/^https:\/\//)
      expect(pin.content_hash).toMatch(/^v1:sha256:[0-9a-f]{64}$/)
      expect(pin.content_hash).toBe(sha256Tagged(readFileSync(fixturePath('sources', dir, file))))
      expect(pinFor(source).contentHash).toBe(pin.content_hash ?? '')
    }
  })
})
