/**
 * The Deno-side entry module, embedded as a string so the compiled binary
 * carries it. It is the only module the sandbox loads from disk; user source
 * arrives as the init frame and is imported through a `data:` URL, which loads
 * without any permission grant. Everything here is plain Deno APIs — the file
 * is never imported by the Bun side.
 */

export const PROTOCOL_VERSION = 1

export const PRELUDE_SOURCE = `
const encoder = new TextEncoder()
const decoder = new TextDecoder()

// stdout carries protocol frames only; user console output goes to stderr.
const writeFrame = (() => {
  let tail = Promise.resolve()
  return (frame) => {
    const bytes = encoder.encode(JSON.stringify(frame) + '\\n')
    tail = tail.then(() => Deno.stdout.write(bytes)).then(() => undefined)
    return tail
  }
})()

const toStderr = (...parts) => {
  const line = parts.map((part) => (typeof part === 'string' ? part : JSON.stringify(part))).join(' ')
  Deno.stderr.write(encoder.encode(line + '\\n'))
}
console.log = toStderr
console.info = toStderr
console.warn = toStderr
console.error = toStderr
console.debug = toStderr

const pending = new Map()
let nextId = 0
let initResolve
const init = new Promise((resolve) => { initResolve = resolve })

async function readFrames() {
  let buffer = ''
  for await (const chunk of Deno.stdin.readable) {
    buffer += decoder.decode(chunk, { stream: true })
    let newline = buffer.indexOf('\\n')
    while (newline >= 0) {
      const line = buffer.slice(0, newline)
      buffer = buffer.slice(newline + 1)
      newline = buffer.indexOf('\\n')
      if (!line.trim()) continue
      let frame
      try { frame = JSON.parse(line) } catch { continue }
      if (frame.t === 'init') initResolve(frame)
      else if (frame.t === 'call_result') {
        const resolve = pending.get(frame.id)
        if (resolve) { pending.delete(frame.id); resolve(frame.result) }
      }
    }
  }
}
readFrames()

function call(profile, request) {
  if (typeof profile !== 'string') throw new TypeError('call(profile, request): profile must be a string')
  const id = nextId++
  return new Promise((resolve) => {
    pending.set(id, resolve)
    writeFrame({ t: 'call', id, profile, request: request ?? {} })
  })
}

const frame = await init
try {
  const mod = await import('data:application/typescript;base64,' + frame.script)
  if (typeof mod.default !== 'function') {
    await writeFrame({ t: 'fail', message: 'the script has no default export function' })
    Deno.exit(0)
  }
  const value = await mod.default({ params: frame.params, api: { call } })
  await writeFrame({ t: 'done', value: value === undefined ? null : value })
} catch (error) {
  const message = error instanceof Error ? error.message : String(error)
  const stack = error instanceof Error && error.stack ? String(error.stack) : undefined
  await writeFrame({ t: 'fail', message, stack })
}
Deno.exit(0)
`
