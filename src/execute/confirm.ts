import { createHash, randomBytes, timingSafeEqual } from 'node:crypto'
import { createInterface } from 'node:readline'
import { LIMITS } from '../policy/limits'
import {
  type RequestPreview,
  type SanitizedRequest,
  previewOf,
  requestBindingText,
} from './sanitize'

/**
 * Confirmation is an injected channel. There are exactly two production
 * implementations — a TTY prompt and MCP elicitation — and no CLI flag,
 * environment variable, or configuration key selects one.
 */

export type ChannelLabel = 'tty' | 'mcp-elicitation' | 'test'

export interface ConfirmationChannel {
  readonly label: ChannelLabel
  /** Present the sanitized preview and report accept or decline. */
  confirm(preview: RequestPreview): Promise<boolean>
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
        stdout.write(`\nAPImanac wants to send this request:\n\n${preview.summary}\n\n`)
        readline.question('Send it? [y/N] ', (answer) => {
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
  answer: boolean | ((preview: RequestPreview) => boolean),
): ConfirmationChannel {
  return {
    label: 'test',
    confirm: async (preview) => (typeof answer === 'function' ? answer(preview) : answer),
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

function bindingOf(request: SanitizedRequest, session: string, expiresAt: number): Buffer {
  return createHash('sha256')
    .update(requestBindingText(request))
    .update('\0')
    .update(session)
    .update('\0')
    .update(String(expiresAt))
    .digest()
}

/**
 * In-memory only, so a restart invalidates every outstanding token. Tokens are
 * minted by the confirmation stage and consumed by the execution stage of the
 * same operation.
 */
export class ApprovalTokens {
  private readonly live = new Set<ApprovalToken>()

  constructor(
    private readonly session: string,
    private readonly ttlMs: number = LIMITS.approvalTokenTtlMs,
    private readonly now: () => number = () => Date.now(),
  ) {}

  mint(request: SanitizedRequest): ApprovalToken {
    const expiresAt = this.now() + this.ttlMs
    const token = new ApprovalToken(
      randomBytes(32),
      bindingOf(request, this.session, expiresAt),
      this.session,
      expiresAt,
    )
    this.live.add(token)
    return token
  }

  /** Single-use: a successful check removes the token. */
  consume(token: ApprovalToken | undefined, request: SanitizedRequest): TokenCheck {
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
    const expected = bindingOf(request, this.session, token.expiresAt)
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
