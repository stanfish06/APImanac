import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { z } from 'zod'
import { PRELUDE_SOURCE, PROTOCOL_VERSION } from './prelude'

/**
 * The sandbox: one Deno subprocess per run, spawned under an explicit
 * hardening contract, speaking newline-delimited JSON over stdio. The child is
 * hostile — user code shares its stdout — so this decoder, not the injected
 * client, is the enforcement seam: every frame is size-capped before parsing,
 * schema-checked, and id-tracked, and nothing decoded here is trusted.
 */

export const SANDBOX_LIMITS = {
  /** Maximum encoded frame line, enforced before JSON parsing. */
  maxFrameBytes: 1024 * 1024,
  /** Maximum concurrently outstanding calls. */
  maxInFlight: 16,
  /** Retained tail of the child's stderr. */
  maxStderrBytes: 16 * 1024,
  /** Grace between SIGTERM and SIGKILL. */
  killGraceMs: 2000,
} as const

/** Supported Deno range; semantics outside it are unverified, so refuse. */
export const DENO_MIN_MAJOR = 2
export const DENO_MAX_MAJOR = 2

/**
 * The spawn contract's flag set: no permission grants, no configuration or
 * lockfile discovery, and every dependency scheme disabled. The prelude and a
 * `data:` import are the only module loads that can succeed.
 */
export const DENO_FLAGS = [
  'run',
  '--quiet',
  '--no-prompt',
  '--no-config',
  '--no-lock',
  '--no-npm',
  '--no-remote',
  '--cached-only',
  '--node-modules-dir=none',
] as const

export interface ResolvedDeno {
  readonly binary: string
  readonly version: string
}

export type DenoResolution =
  | { readonly ok: true; readonly deno: ResolvedDeno }
  | { readonly ok: false; readonly message: string }

let cachedResolution: DenoResolution | undefined

/**
 * The child's environment: the parent's, minus every variable that could steer
 * Deno's own startup — its permission-decision broker, config, cache, auth, and
 * proxy settings. `DENO_DIR` is then forced to a per-run directory. User code
 * still cannot read this environment (no `--allow-env`); the strip is
 * defense-in-depth for the runtime itself, and the denylist rather than a
 * two-variable allowlist so shim-based installs (mise, asdf) keep working.
 */
const ENV_STRIP =
  /^(DENO_|NODE_|NPM_|npm_|HTTP_PROXY$|HTTPS_PROXY$|http_proxy$|https_proxy$|ALL_PROXY$|all_proxy$)/

export function childEnv(denoDir: string): Record<string, string> {
  const env: Record<string, string> = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue
    if (ENV_STRIP.test(key)) continue
    env[key] = value
  }
  env.DENO_DIR = denoDir
  env.NO_COLOR = '1'
  return env
}

/** Resolve one absolute Deno binary and check that same binary's version. */
export function resolveDeno(refresh = false): DenoResolution {
  if (cachedResolution && !refresh) return cachedResolution
  const binary = Bun.which('deno')
  if (!binary) {
    cachedResolution = {
      ok: false,
      message:
        'workflow scripts need Deno, which is not on PATH; install it (e.g. `mise use deno@2`) and retry',
    }
    return cachedResolution
  }
  let output: string
  try {
    // Version detection inherits the full environment so a version-manager shim
    // can resolve; the sandbox spawn (below) strips the dangerous variables.
    output = new TextDecoder().decode(Bun.spawnSync([binary, '--version']).stdout)
  } catch (error) {
    cachedResolution = { ok: false, message: `\`${binary} --version\` failed: ${String(error)}` }
    return cachedResolution
  }
  const match = output.match(/^deno (\d+)\.(\d+)\.(\d+)/)
  if (!match) {
    cachedResolution = { ok: false, message: `\`${binary} --version\` output was unrecognized` }
    return cachedResolution
  }
  const major = Number(match[1])
  if (major < DENO_MIN_MAJOR || major > DENO_MAX_MAJOR) {
    cachedResolution = {
      ok: false,
      message: `Deno ${match[1]}.${match[2]}.${match[3]} at ${binary} is outside the supported ${DENO_MIN_MAJOR}.x range`,
    }
    return cachedResolution
  }
  // Dereference to the real executable: a version-manager shim (mise, asdf)
  // resolves its version from the project directory, which the sandbox — running
  // in a disposable cwd with a stripped environment — cannot reach.
  let real = binary
  try {
    const resolved = new TextDecoder()
      .decode(Bun.spawnSync([binary, 'eval', '--no-prompt', 'console.log(Deno.execPath())']).stdout)
      .trim()
    if (resolved) real = resolved
  } catch {
    // Keep the resolved-by-PATH binary; the spawn will surface any real failure.
  }
  cachedResolution = {
    ok: true,
    deno: { binary: real, version: `${match[1]}.${match[2]}.${match[3]}` },
  }
  return cachedResolution
}

/** Test-only: drop the memoized resolution. */
export function resetDenoResolutionForTests(): void {
  cachedResolution = undefined
}

/** The call shape a script may request. `response_mode` is deliberately absent: inline only. */
export const BridgeCallRequest = z
  .object({
    method: z.string().min(1).max(16).default('GET'),
    path: z.string().min(1).max(4096),
    query: z.record(z.string().max(256), z.string().max(8192)).optional(),
    headers: z.record(z.string().max(256), z.string().max(8192)).optional(),
    body_json: z.unknown().optional(),
    body_text: z.string().optional(),
    body_form: z.record(z.string().max(256), z.string().max(65536)).optional(),
  })
  .strict()

export type BridgeCallRequest = z.infer<typeof BridgeCallRequest>

const CallFrame = z
  .object({
    t: z.literal('call'),
    id: z.number().int().nonnegative(),
    profile: z.string().min(1).max(256),
    request: z.unknown(),
  })
  .strict()

const DoneFrame = z.object({ t: z.literal('done'), value: z.unknown() }).strict()

const FailFrame = z
  .object({
    t: z.literal('fail'),
    message: z.string().max(8192),
    stack: z.string().max(16384).optional(),
  })
  .strict()

const ChildFrame = z.discriminatedUnion('t', [CallFrame, DoneFrame, FailFrame])

export type SandboxResult =
  | { readonly kind: 'done'; readonly value: unknown; readonly stderr: string }
  | { readonly kind: 'fail'; readonly message: string; readonly stderr: string }
  | { readonly kind: 'protocol_error'; readonly message: string; readonly stderr: string }
  | { readonly kind: 'cancelled'; readonly stderr: string }
  | { readonly kind: 'spawn_error'; readonly message: string }

export interface SandboxRun {
  readonly deno: ResolvedDeno
  readonly scriptSource: Buffer
  readonly params: Readonly<Record<string, unknown>>
  /**
   * Executes one bridged call. The returned value must already be sanitized:
   * it is serialized verbatim into the child's `call_result` frame.
   */
  readonly onCall: (profile: string, request: BridgeCallRequest) => Promise<unknown>
  readonly signal?: AbortSignal
}

class StderrRing {
  private chunks: Buffer[] = []
  private bytes = 0

  push(chunk: Buffer): void {
    this.chunks.push(chunk)
    this.bytes += chunk.byteLength
    while (this.bytes > SANDBOX_LIMITS.maxStderrBytes && this.chunks.length > 0) {
      const first = this.chunks[0] as Buffer
      const excess = this.bytes - SANDBOX_LIMITS.maxStderrBytes
      if (first.byteLength <= excess) {
        this.chunks.shift()
        this.bytes -= first.byteLength
      } else {
        this.chunks[0] = first.subarray(excess)
        this.bytes -= excess
      }
    }
  }

  text(): string {
    return Buffer.concat(this.chunks).toString('utf8')
  }
}

/** Spawn the sandbox, run the protocol to completion, and always reap the child. */
export async function runSandbox(run: SandboxRun): Promise<SandboxResult> {
  const runDir = mkdtempSync(join(tmpdir(), 'apimanac-run-'))
  const denoDir = join(runDir, 'deno-dir')
  const workDir = join(runDir, 'work')
  mkdirSync(denoDir)
  mkdirSync(workDir)
  const preludePath = join(runDir, 'prelude.ts')
  writeFileSync(preludePath, PRELUDE_SOURCE)

  let child: ReturnType<typeof Bun.spawn>
  try {
    child = Bun.spawn([run.deno.binary, ...DENO_FLAGS, preludePath], {
      cwd: workDir,
      // No DENO_*, proxy, npm, or node variable reaches the child, so nothing
      // outside this process can change the runtime's permission or module rules.
      env: childEnv(denoDir),
      stdin: 'pipe',
      stdout: 'pipe',
      stderr: 'pipe',
    })
  } catch (error) {
    rmSync(runDir, { recursive: true, force: true })
    return { kind: 'spawn_error', message: `the sandbox failed to start: ${String(error)}` }
  }

  const stderr = new StderrRing()
  const stderrDrain = (async () => {
    for await (const chunk of child.stderr as ReadableStream<Uint8Array>) {
      stderr.push(Buffer.from(chunk))
    }
  })().catch(() => undefined)

  const stdin = child.stdin as unknown as {
    write(text: string): void
    flush(): Promise<void> | number
  }
  let writeTail = Promise.resolve()
  const writeFrame = (frame: unknown): Promise<void> => {
    writeTail = writeTail
      .then(async () => {
        stdin.write(`${JSON.stringify(frame)}\n`)
        await stdin.flush()
      })
      .catch(() => undefined)
    return writeTail
  }

  const seenIds = new Set<number>()
  let inFlight = 0
  let settled: SandboxResult | undefined
  const callWork: Promise<void>[] = []

  const kill = async (): Promise<void> => {
    try {
      child.kill('SIGTERM')
    } catch {
      /* already gone */
    }
    const grace = new Promise<void>((resolve) => setTimeout(resolve, SANDBOX_LIMITS.killGraceMs))
    await Promise.race([child.exited.then(() => undefined), grace])
    try {
      child.kill('SIGKILL')
    } catch {
      /* already gone */
    }
  }

  const onAbort = () => {
    settled ??= { kind: 'cancelled', stderr: stderr.text() }
    void kill()
  }
  if (run.signal?.aborted) onAbort()
  run.signal?.addEventListener('abort', onAbort, { once: true })

  const protocolFailure = (message: string): void => {
    settled ??= { kind: 'protocol_error', message, stderr: stderr.text() }
    void kill()
  }

  const handleFrame = (line: string): void => {
    if (settled) return
    let parsed: unknown
    try {
      parsed = JSON.parse(line)
    } catch {
      protocolFailure('the sandbox wrote a line that is not a protocol frame')
      return
    }
    const frame = ChildFrame.safeParse(parsed)
    if (!frame.success) {
      protocolFailure('the sandbox wrote a frame outside the protocol')
      return
    }
    const value = frame.data
    if (value.t === 'done') {
      settled = { kind: 'done', value: value.value, stderr: stderr.text() }
      void kill()
      return
    }
    if (value.t === 'fail') {
      settled = { kind: 'fail', message: value.message, stderr: stderr.text() }
      void kill()
      return
    }
    if (seenIds.has(value.id)) {
      protocolFailure(`the sandbox reused call id ${value.id}`)
      return
    }
    seenIds.add(value.id)
    if (inFlight >= SANDBOX_LIMITS.maxInFlight) {
      protocolFailure(`the sandbox exceeded ${SANDBOX_LIMITS.maxInFlight} calls in flight`)
      return
    }
    const request = BridgeCallRequest.safeParse(value.request)
    if (!request.success) {
      // An invalid request shape refuses that call; the run continues.
      void writeFrame({
        t: 'call_result',
        id: value.id,
        result: {
          outcome: 'unsupported_request',
          message: `invalid call request: ${request.error.issues
            .map((issue) => `${issue.path.join('.') || '$'}: ${issue.message}`)
            .join('; ')}`,
        },
      })
      return
    }
    inFlight += 1
    callWork.push(
      run
        .onCall(value.profile, request.data)
        .catch((error) => ({
          outcome: 'policy_failure',
          message: `the call failed inside APImanac: ${String(error)}`,
        }))
        .then((result) => {
          inFlight -= 1
          if (!settled) void writeFrame({ t: 'call_result', id: value.id, result })
        }),
    )
  }

  const stdoutDrain = (async () => {
    let buffer = Buffer.alloc(0)
    for await (const chunk of child.stdout as ReadableStream<Uint8Array>) {
      if (settled) break
      buffer = Buffer.concat([buffer, Buffer.from(chunk)])
      let newline = buffer.indexOf(0x0a)
      while (newline >= 0) {
        const line = buffer.subarray(0, newline)
        buffer = buffer.subarray(newline + 1)
        if (line.byteLength > SANDBOX_LIMITS.maxFrameBytes) {
          protocolFailure('the sandbox wrote a frame beyond the size bound')
          return
        }
        const text = line.toString('utf8')
        if (text.trim()) handleFrame(text)
        if (settled) return
        newline = buffer.indexOf(0x0a)
      }
      if (buffer.byteLength > SANDBOX_LIMITS.maxFrameBytes) {
        protocolFailure('the sandbox wrote a frame beyond the size bound')
        return
      }
    }
  })().catch(() => undefined)

  void writeFrame({
    v: PROTOCOL_VERSION,
    t: 'init',
    script: run.scriptSource.toString('base64'),
    params: run.params,
  })

  await child.exited
  await Promise.race([stdoutDrain, new Promise((resolve) => setTimeout(resolve, 250))])
  await Promise.race([stderrDrain, new Promise((resolve) => setTimeout(resolve, 250))])
  await Promise.allSettled(callWork)
  run.signal?.removeEventListener('abort', onAbort)
  rmSync(runDir, { recursive: true, force: true })

  if (settled) return settled
  return {
    kind: 'protocol_error',
    message: `the sandbox exited (code ${child.exitCode ?? 'unknown'}) without a result`,
    stderr: stderr.text(),
  }
}
