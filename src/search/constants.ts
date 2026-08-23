/**
 * Ranking coefficients. The contract fixes which comparisons must hold when
 * everything else is equal, not these values; they are tuned against
 * `tests/fixtures/search/queries.yaml` and changing them changes only this file.
 */

/** FTS5 bm25 column weights, in table column order. */
export const COLUMN_WEIGHTS = {
  api_id: 0,
  name: 12,
  aliases: 9,
  description: 1.5,
  categories: 5,
  tags: 5,
  provenance: 0.6,
  capabilities: 2.5,
} as const

export const BOOSTS = {
  /** A reviewer curated this record rather than importing it. */
  curated: 2.4,
  /** The record has at least one verified execution profile. */
  verified: 1.8,
  /** A local credential resolves, or the profile needs none. */
  ready: 1.2,
  /** Most recent health observation. */
  health: {
    healthy: 0.9,
    unknown: 0,
    rate_limited: -0.2,
    auth_required: -0.3,
    degraded: -0.6,
    unreachable: -1.1,
  },
  /** Lifecycle penalties keep dead records findable but below live ones. */
  lifecycle: {
    active: 0,
    deprecated: -0.8,
    gone: -1.6,
    merged: 0,
  },
  /** A working-tree-only record is visible but does not outrank reviewed ones. */
  draft: -0.3,
} as const

/** Every boost the score adds is non-negative after this shift. */
export const BOOST_FLOOR = 2

export const DEFAULT_LIMIT = 10
/** The one result bound both the CLI and the MCP tool clamp to. */
export const MAX_LIMIT = 25
