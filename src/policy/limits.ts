/**
 * Measurable defaults, overridable per profile where the specs allow. The specs
 * bound the behavior — bounded, owner-only, evicted — not these numbers.
 */

export const LIMITS = {
  /** Decompressed bytes an `inline` response may reach. */
  inlineMaxBytes: 4 * 1024 * 1024,
  /** Compressed bytes an `inline` response may reach. */
  inlineMaxCompressedBytes: 2 * 1024 * 1024,
  /** Bytes a `file` response may reach. */
  fileMaxBytes: 128 * 1024 * 1024,
  requestTimeoutMs: 30_000,
  connectTimeoutMs: 10_000,
  maxRedirects: 5,
  requestBodyMaxBytes: 1024 * 1024,
  specificationMaxBytes: 8 * 1024 * 1024,
  cacheQuotaBytes: 512 * 1024 * 1024,
  cacheDefaultTtlSeconds: 300,
  approvalTokenTtlMs: 120_000,
  healthObservationsPerProfile: 50,
} as const
