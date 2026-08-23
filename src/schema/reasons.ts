/**
 * Versioned rejection reason vocabularies, one per adapter. Changing or removing
 * a code requires bumping that adapter's version and migrating its ledgers.
 */

export interface ReasonVocabulary {
  readonly version: number
  readonly codes: readonly string[]
}

export const PUBLIC_APIS_REASONS: ReasonVocabulary = {
  version: 1,
  codes: [
    'missing_name',
    'missing_link',
    'invalid_link',
    'unusable_category',
    'duplicate_entry',
    'schema_mismatch',
  ],
}

export const NANGO_REASONS: ReasonVocabulary = {
  version: 1,
  codes: [
    'unsupported_auth_mode',
    'unsupported_template_construct',
    'connection_configuration_required',
    'missing_base_url',
    'invalid_base_url',
    'missing_display_name',
    'schema_mismatch',
  ],
}

export const APIS_GURU_REASONS: ReasonVocabulary = {
  version: 1,
  codes: [
    'no_preferred_version',
    'missing_spec_url',
    'spec_too_large',
    'spec_unparseable',
    'unsupported_spec_version',
    'no_servers_in_spec',
    'invalid_server_url',
    'schema_mismatch',
  ],
}

export const REASON_VOCABULARIES: Record<string, ReasonVocabulary> = {
  'public-apis': PUBLIC_APIS_REASONS,
  nango: NANGO_REASONS,
  'apis-guru': APIS_GURU_REASONS,
}

/** Ledger rejection detail is truncated to this many characters when written. */
export const REJECTION_DETAIL_MAX = 200
