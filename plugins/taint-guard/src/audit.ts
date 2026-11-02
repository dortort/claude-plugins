import type { AuditEntry, AuditFs } from './types.ts'

export const ROLL_BYTES = 3.5 * 1024 * 1024
export const ARGS_SNIPPET_MAX = 200

const NON_ARGUMENT_FIELDS = new Set(['tool', 'tool_use_id', 'agentId', 'consent'])

function isOmitted(value: unknown): boolean {
  return value === undefined || typeof value === 'function' || typeof value === 'symbol'
}

function canonical(value: unknown): string {
  if (value !== null && typeof value === 'object' && typeof (value as { toJSON?: unknown }).toJSON === 'function') {
    value = (value as { toJSON: () => unknown }).toJSON()
  }
  if (value === null || isOmitted(value)) return 'null'
  if (typeof value !== 'object') return JSON.stringify(value)
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']'
  const obj = value as Record<string, unknown>
  const parts: string[] = []
  for (const key of Object.keys(obj).sort()) {
    const v = obj[key]
    if (isOmitted(v)) continue
    parts.push(JSON.stringify(key) + ':' + canonical(v))
  }
  return '{' + parts.join(',') + '}'
}

/** JSON with object keys sorted recursively and no whitespace. */
export function canonicalJson(value: unknown): string {
  return canonical(value)
}

/** A tool.call event's fields less tool, tool_use_id, agentId and consent. */
export function callArguments(e: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const [key, value] of Object.entries(e)) {
    if (!NON_ARGUMENT_FIELDS.has(key)) out[key] = value
  }
  return out
}

function toHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes)
  let out = ''
  for (const b of view) out += b.toString(16).padStart(2, '0')
  return out
}

function fromHex(hex: string): Uint8Array<ArrayBuffer> {
  if (hex.length === 0 || hex.length % 2 !== 0 || !/^[0-9a-fA-F]+$/.test(hex)) {
    throw new Error('TaintGuard: the audit key is not hex')
  }
  const out = new Uint8Array(new ArrayBuffer(hex.length / 2))
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

/** A fresh random 256-bit HMAC-SHA-256 key, as 64 hex characters. */
export async function generateKeyHex(): Promise<string> {
  return toHex(crypto.getRandomValues(new Uint8Array(32)))
}

const SHA256_BLOCK = 64

async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const total = parts.reduce((sum, part) => sum + part.length, 0)
  const joined = new Uint8Array(new ArrayBuffer(total))
  let at = 0
  for (const part of parts) {
    joined.set(part, at)
    at += part.length
  }
  return new Uint8Array(await crypto.subtle.digest('SHA-256', joined))
}

/** HMAC-SHA-256 of the text under the hex key, as hex, built on digest (RFC 2104): the hooks runtime has no subtle.sign. */
export async function hmacHex(keyHex: string, text: string): Promise<string> {
  let key: Uint8Array = fromHex(keyHex)
  if (key.length > SHA256_BLOCK) key = await sha256(key)
  const inner = new Uint8Array(SHA256_BLOCK)
  const outer = new Uint8Array(SHA256_BLOCK)
  for (let i = 0; i < SHA256_BLOCK; i++) {
    const byte = key[i] ?? 0
    inner[i] = byte ^ 0x36
    outer[i] = byte ^ 0x5c
  }
  return toHex(await sha256(outer, await sha256(inner, new TextEncoder().encode(text))))
}

export function argsSnippet(args: unknown, max: number = ARGS_SNIPPET_MAX): string {
  return canonicalJson(args).slice(0, max)
}

function stripTrailingSlash(dir: string): string {
  return dir.length > 1 && (dir.endsWith('/') || dir.endsWith('\\')) ? dir.slice(0, -1) : dir
}

/** The Claude config directory: CLAUDE_CONFIG_DIR, else ~/.claude, or null when no home is known. */
export function configDirFrom(env: { CLAUDE_CONFIG_DIR?: string; HOME?: string; USERPROFILE?: string }): string | null {
  if (env.CLAUDE_CONFIG_DIR) return stripTrailingSlash(env.CLAUDE_CONFIG_DIR)
  const home = env.HOME || env.USERPROFILE
  if (!home) return null
  const base = stripTrailingSlash(home)
  return (base === '/' ? '' : base) + '/.claude'
}

export function auditPath(configDir: string, sessionId: string): string {
  const safe = sessionId.replace(/[^A-Za-z0-9._-]/g, '_') || '_'
  return `${configDir}/taint-guard/audit/${safe}.jsonl`
}

export type AuditLog = {
  append(entry: AuditEntry): void
  flush(): Promise<void>
  tail(n: number): Promise<AuditEntry[]>
  setPath(path: string): Promise<void>
  path(): string
  pending(): number
}

/** A buffered JSONL log that rolls to `<path>.1` past rollBytes. */
export function createAuditLog(fs: AuditFs, options: { path: string; rollBytes?: number }): AuditLog {
  const rollBytes = options.rollBytes ?? ROLL_BYTES
  const encoder = new TextEncoder()
  let current = options.path
  let buffer: string[] = []
  let loaded = false
  let content = ''
  let contentBytes = 0
  let chain: Promise<unknown> = Promise.resolve()

  const enqueue = <T>(task: () => Promise<T>): Promise<T> => {
    const run = chain.then(task)
    chain = run.catch(() => undefined)
    return run
  }

  const ensureLoaded = async () => {
    if (loaded) return
    const text = (await fs.read(current)) ?? ''
    content = text
    contentBytes = encoder.encode(text).length
    loaded = true
  }

  const doFlush = async () => {
    if (buffer.length === 0) return
    await ensureLoaded()
    const count = buffer.length
    const added = buffer.slice(0, count).join('\n') + '\n'
    const separator = content.length > 0 && !content.endsWith('\n') ? '\n' : ''
    const addedBytes = encoder.encode(separator + added).length
    if (content.length > 0 && contentBytes + addedBytes > rollBytes) {
      await fs.write(current + '.1', content)
      await fs.write(current, added)
      content = added
      contentBytes = encoder.encode(added).length
    } else {
      const next = content + separator + added
      await fs.write(current, next)
      content = next
      contentBytes += addedBytes
    }
    buffer = buffer.slice(count)
  }

  return {
    append(entry) {
      try {
        buffer.push(JSON.stringify(entry))
      } catch {}
    },
    flush() {
      return enqueue(doFlush)
    },
    tail(n) {
      return enqueue(async () => {
        if (!(n > 0)) return []
        await ensureLoaded()
        const lines = [...content.split('\n'), ...buffer]
        const out: AuditEntry[] = []
        for (let i = lines.length - 1; i >= 0 && out.length < n; i--) {
          const line = lines[i]
          if (!line) continue
          try {
            const parsed: unknown = JSON.parse(line)
            if (parsed !== null && typeof parsed === 'object' && !Array.isArray(parsed)) out.push(parsed as AuditEntry)
          } catch {
            continue
          }
        }
        return out.reverse()
      })
    },
    setPath(path) {
      return enqueue(async () => {
        let failure: unknown = null
        try {
          await doFlush()
        } catch (error) {
          failure = error ?? new Error('TaintGuard: audit flush failed')
        }
        if (path !== current) {
          current = path
          loaded = false
          content = ''
          contentBytes = 0
        }
        if (failure !== null) throw failure
      })
    },
    path() {
      return current
    },
    pending() {
      return buffer.length
    },
  }
}
