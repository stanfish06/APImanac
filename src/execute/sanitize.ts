import type { ResponseMode } from '../schema/vocab'

/**
 * Everything that crosses the executor boundary is built from this value.
 * Credential-bearing request objects never leave `src/execute/`, so results,
 * errors, previews, cache metadata, and log lines carry no secret to scrub.
 */

export interface SanitizedRequest {
  readonly api_id: string
  readonly profile_id: string
  readonly account?: string
  readonly method: string
  readonly origin: string
  readonly path: string
  /** Caller-supplied query parameters only; a credential parameter is never here. */
  readonly query: readonly (readonly [string, string])[]
  /** Names only, and only of headers the caller supplied. */
  readonly header_names: readonly string[]
  readonly body?: { readonly content_type: string; readonly bytes: number; readonly hash: string }
  readonly response_mode: ResponseMode
  readonly redirect_policy_hash: string
}

export interface RequestPreview extends SanitizedRequest {
  readonly kind: 'request'
  readonly decision: 'confirm'
  readonly summary: string
}

export function previewOf(request: SanitizedRequest): RequestPreview {
  const query = request.query.map(([name, value]) => `${name}=${value}`).join('&')
  const body = request.body
    ? `${request.body.content_type}, ${request.body.bytes} byte(s)`
    : 'no body'
  return {
    ...request,
    kind: 'request',
    decision: 'confirm',
    summary: [
      `${request.method} ${request.origin}${request.path}${query ? `?${query}` : ''}`,
      `profile: ${request.api_id}/${request.profile_id}${request.account ? ` account: ${request.account}` : ''}`,
      `headers: ${request.header_names.length ? request.header_names.join(', ') : 'none'}`,
      `body: ${body}`,
      `response mode: ${request.response_mode}`,
    ].join('\n'),
  }
}

/** Stable text form used to bind an approval token to a request. */
export function requestBindingText(request: SanitizedRequest): string {
  return JSON.stringify({
    api_id: request.api_id,
    profile_id: request.profile_id,
    account: request.account ?? null,
    method: request.method,
    origin: request.origin,
    path: request.path,
    query: request.query,
    header_names: [...request.header_names].sort(),
    body: request.body?.hash ?? null,
    response_mode: request.response_mode,
    redirect_policy_hash: request.redirect_policy_hash,
  })
}
