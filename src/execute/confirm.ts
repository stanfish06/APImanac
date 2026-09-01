import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { createInterface } from 'node:readline'
import { LIMITS } from '../policy/limits'
import { previewOf, requestBindingText, type SanitizedRequest } from './sanitize'

/**
 * Confirmation is an injected channel. There are exactly two production
 * implementations — a TTY prompt and MCP elicitation — and no CLI flag,
 * environment variable, or configuration key selects one.
 */

export type ChannelLabel = 'tty' | 'mcp-elicitation' | 'test'

/** What a channel presents: a sanitized request, or an ad-hoc script subject. */
export interface ConfirmationPreview {
  readonly kind: 'request' | 'script'
  readonly summary: string
}

/** The question a channel asks, phrased per preview kind. */
export function confirmationQuestion(preview: ConfirmationPreview): string {
  return preview.kind === 'script'
    ? 'APImanac wants to run this script'
    : 'APImanac wants to send this request'
}

export interface ConfirmationChannel {
  readonly label: ChannelLabel
  /** Present the sanitized preview and report accept or decline. */
  confirm(preview: ConfirmationPreview): Promise<boolean>
}

/** Constructed only when stdin is a controlling terminal. */
export function ttyChannel(
  stdin: NodeJS.ReadStream = process.stdin,
  stdout: NodeJS.WriteStream = process.stdout,
): ConfirmationChannel | undefined {
  if (!stdin.isTTY) return undefined
  return {
    label: 'tty',
    confirm(preview) {
      return new Promise<boolean>((resolve) => {
        const readline = createInterface({ input: stdin, output: stdout })
        stdout.write(`\n${confirmationQuestion(preview)}:\n\n${preview.summary}\n\n`)
        const question = preview.kind === 'script' ? 'Run it? [y/N] ' : 'Send it? [y/N] '
        readline.question(question, (answer) => {
          readline.close()
          resolve(/^y(es)?$/i.test(answer.trim()))
        })
      })
    },
  }
}

/**
 * Test-only channel, reachable solely through the library API. Nothing reads
 * argv or the environment to select it.
 */
export function testChannel(
  answer: boolean | ((preview: ConfirmationPreview) => boolean),
): ConfirmationChannel {
  return {
    label: 'test',
    confirm: async (preview) => (typeof answer === 'function' ? answer(preview) : answer),
  }
}

/** One prompt at a time: concurrent confirmations queue rather than interleave. */
export function serializedChannel(channel: ConfirmationChannel): ConfirmationChannel {
  let tail: Promise<unknown> = Promise.resolve()
  return {
    label: channel.label,
    confirm(preview) {
      const next = tail.then(() => channel.confirm(preview))
      tail = next.catch(() => undefined)
      return next
    },
  }
}

/**
 * An approval token. It is an in-process object, never a string a caller could
 * supply: there is no way to construct one from a tool input, a CLI argument,
 * or an environment value.
 */
export class ApprovalToken {
  /** @internal */
  constructor(
    readonly nonce: Buffer,
    readonly binding: Buffer,
    readonly session: string,
    readonly expiresAt: number,
  ) {}
}

export interface TokenRejection {
  readonly ok: false
  readonly code: 'unknown' | 'replayed' | 'expired' | 'rebound' | 'wrong_session'
  readonly message: string
}

export type TokenCheck = { ok: true } | TokenRejection

function bindingOf(text: string, session: string, expiresAt: number): Buffer {
  return createHash('sha256')
    .update(text)
    .update('\0')
    .update(session)
    .update('\0')
    .update(String(expiresAt))
    .digest()
}

/**
 * In-memory only, so a restart invalidates every outstanding token. Tokens are
 * minted by the confirmation stage and consumed by the execution stage of the
 * same operation. One vault binds one subject shape through its binding text.
 */
class TokenVault<Subject> {
  private readonly live = new Set<ApprovalToken>()

  constructor(
    private readonly bindingTextOf: (subject: Subject) => string,
    private readonly session: string,
    private readonly ttlMs: number = LIMITS.approvalTokenTtlMs,
    private readonly now: () => number = () => Date.now(),
  ) {}

  mint(subject: Subject): ApprovalToken {
    const expiresAt = this.now() + this.ttlMs
    const token = new ApprovalToken(
      randomBytes(32),
      bindingOf(this.bindingTextOf(subject), this.session, expiresAt),
      this.session,
      expiresAt,
    )
    this.live.add(token)
    return token
  }

  /** Single-use: a successful check removes the token. */
  consume(token: ApprovalToken | undefined, subject: Subject): TokenCheck {
    if (!token) {
      return { ok: false, code: 'unknown', message: 'no approval was recorded for this request' }
    }
    if (!this.live.has(token)) {
      return { ok: false, code: 'replayed', message: 'this approval has already been used' }
    }
    if (token.session !== this.session) {
      this.live.delete(token)
      return {
        ok: false,
        code: 'wrong_session',
        message: 'this approval belongs to another session',
      }
    }
    if (this.now() > token.expiresAt) {
      this.live.delete(token)
      return { ok: false, code: 'expired', message: 'this approval expired; confirm again' }
    }
    const expected = bindingOf(this.bindingTextOf(subject), this.session, token.expiresAt)
    if (
      expected.byteLength !== token.binding.byteLength ||
      !timingSafeEqual(expected, token.binding)
    ) {
      this.live.delete(token)
      return {
        ok: false,
        code: 'rebound',
        message: 'the request changed after it was approved; confirm the new request',
      }
    }
    this.live.delete(token)
    return { ok: true }
  }

  get outstanding(): number {
    return this.live.size
  }
}

export class ApprovalTokens extends TokenVault<SanitizedRequest> {
  constructor(session: string, ttlMs?: number, now?: () => number) {
    super(requestBindingText, session, ttlMs, now)
  }
}

export interface ConfirmOutcome {
  readonly accepted: boolean
  readonly token?: ApprovalToken
}

/** Ask the channel, and mint a token only after an accept. */
export async function confirmRequest(
  channel: ConfirmationChannel,
  tokens: ApprovalTokens,
  request: SanitizedRequest,
): Promise<ConfirmOutcome> {
  const accepted = await channel.confirm(previewOf(request))
  return accepted ? { accepted, token: tokens.mint(request) } : { accepted: false }
}

/**
 * The exact subject an ad-hoc script approval binds: source bytes, normalized
 * parameters, pinned bindings, and the resolved runtime. Any post-approval
 * mutation produces a different binding text, so the token cannot be consumed.
 */
export interface ScriptApprovalSubject {
  readonly source: Buffer
  readonly params: Readonly<Record<string, unknown>>
  readonly bindings: readonly { readonly profile: string; readonly blob_sha256: string }[]
  readonly runtime: string
}

/** An ad-hoc source larger than this refuses rather than truncating the preview. */
export const SCRIPT_SOURCE_MAX_BYTES = 32768

export function scriptBindingText(subject: ScriptApprovalSubject): string {
  return JSON.stringify({
    source_sha256: createHash('sha256').update(subject.source).digest('hex'),
    params: subject.params,
    bindings: subject.bindings.map((binding) => ({
      profile: binding.profile,
      blob_sha256: binding.blob_sha256,
    })),
    runtime: subject.runtime,
  })
}

/**
 * Escape everything that could make displayed source differ from executed
 * source: C0/C1 controls (except newline and tab), DEL, and Unicode
 * bidirectional overrides. The bytes shown are the bytes approved.
 */
const PREVIEW_ESCAPE =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: matching them to escape them is the point
  /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]/g

export function escapeForPreview(text: string): string {
  return text.replace(
    PREVIEW_ESCAPE,
    (char) => `\\u${char.charCodeAt(0).toString(16).padStart(4, '0')}`,
  )
}

export function scriptPreview(subject: ScriptApprovalSubject): ConfirmationPreview {
  const bindings = subject.bindings
    .map((binding) => `  ${binding.profile} @ ${binding.blob_sha256}`)
    .join('\n')
  return {
    kind: 'script',
    summary: [
      `bindings:\n${bindings}`,
      `params: ${escapeForPreview(JSON.stringify(subject.params))}`,
      `runtime: ${subject.runtime}`,
      `script (${subject.source.byteLength} bytes):`,
      '─'.repeat(40),
      escapeForPreview(subject.source.toString('utf8')),
      '─'.repeat(40),
    ].join('\n'),
  }
}

export class ScriptApprovals extends TokenVault<ScriptApprovalSubject> {
  constructor(session: string, ttlMs?: number, now?: () => number) {
    super(scriptBindingText, session, ttlMs, now)
  }
}

/** Present the full script subject and mint a single-use token on accept. */
export async function confirmScript(
  channel: ConfirmationChannel,
  approvals: ScriptApprovals,
  subject: ScriptApprovalSubject,
): Promise<ConfirmOutcome> {
  const accepted = await channel.confirm(scriptPreview(subject))
  return accepted ? { accepted, token: approvals.mint(subject) } : { accepted: false }
}
