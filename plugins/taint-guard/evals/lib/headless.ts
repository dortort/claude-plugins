import { execFile, execFileSync } from 'node:child_process'
import { existsSync, mkdtempSync, readFileSync, readdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import type { AuditEntry } from '../../src/types.ts'

export const PLUGIN_DIR = resolve(dirname(fileURLToPath(import.meta.url)), '../..')
export const DEFAULT_MODEL = 'haiku'

export const HOST_VARS: readonly string[] = [
  'CLAUDE_CODE_REMOTE',
  'CLAUDECODE',
  'CLAUDE_CODE_SESSION_ID',
  'CLAUDE_CODE_ENTRYPOINT',
  'CLAUDE_CODE_CHILD_SESSION',
  'CLAUDE_AUTO_BACKGROUND_TASKS',
  'CLAUDE_CODE_PLUGIN_DIRS',
  'CLAUDE_CODE_MESSAGING_SOCKET',
  'CLAUDE_CODE_MESSAGING_TOKEN',
  'CLAUDE_CODE_SESSION_ATTENDED',
  'CLAUDE_PID',
  'CLAUDE_EFFORT',
]

export type StreamEvent = { type?: string; subtype?: string; session_id?: string; [key: string]: unknown }

export type ToolCallRecord = {
  id: string
  name: string
  input: Record<string, unknown>
  parentToolUseId: string | null
  resultText?: string
  isError?: boolean
}

export type SessionRun = {
  sessionId: string
  cwd: string
  events: StreamEvent[]
  calls: ToolCallRecord[]
  result: string
  isError: boolean
  numTurns: number
  costUsd: number
  exitCode: number | null
  stderr: string
}

export type SessionOptions = {
  cwd: string
  prompt: string
  pluginOptions: Record<string, unknown>
  allowedTools?: readonly string[]
  mcpServers?: Record<string, unknown>
  model?: string
  withPlugin?: boolean
  timeoutMs?: number
}

export function sessionEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, CLAUDE_CODE_ENABLE_FUNCTION_HOOKS: '1' }
  for (const name of HOST_VARS) delete env[name]
  return env
}

export function configDir(): string {
  return process.env.CLAUDE_CONFIG_DIR ?? join(homedir(), '.claude')
}

export function claudeVersion(): string | null {
  try {
    return execFileSync('claude', ['--version'], { encoding: 'utf8', timeout: 20_000, env: sessionEnv() }).trim()
  } catch {
    return null
  }
}

export function makeTempDir(prefix: string): string {
  return realpathSync.native(mkdtempSync(join(tmpdir(), prefix)))
}

export function projectTranscriptDir(cwd: string): string {
  return join(configDir(), 'projects', cwd.replace(/[^a-zA-Z0-9]/g, '-'))
}

export function transcriptPath(cwd: string, sessionId: string): string {
  return join(projectTranscriptDir(cwd), `${sessionId}.jsonl`)
}

export function auditFile(sessionId: string): string {
  return join(configDir(), 'taint-guard', 'audit', `${sessionId.replace(/[^A-Za-z0-9._-]/g, '_')}.jsonl`)
}

function isolationArgs(model: string): string[] {
  return ['--model', model, '--setting-sources', 'project,local', '--strict-mcp-config']
}

function textOf(content: unknown): string {
  if (typeof content === 'string') return content
  if (!Array.isArray(content)) return ''
  return content
    .map((part: unknown) => {
      const block = part as { type?: string; text?: string }
      return block.type === 'text' ? (block.text ?? '') : ''
    })
    .join('')
}

/** The tool result text without Claude Code's `<tool_use_error>` wrapper. */
export function unwrapError(text: string): string {
  const match = /^<tool_use_error>([\s\S]*)<\/tool_use_error>$/.exec(text.trim())
  return match?.[1] ?? text
}

export function toolCalls(events: readonly StreamEvent[]): ToolCallRecord[] {
  const calls: ToolCallRecord[] = []
  const byId = new Map<string, ToolCallRecord>()
  for (const event of events) {
    const message = event.message as { content?: unknown } | undefined
    if (!Array.isArray(message?.content)) continue
    for (const raw of message.content as unknown[]) {
      const block = raw as { type?: string; id?: string; name?: string; input?: unknown; tool_use_id?: string; content?: unknown; is_error?: boolean }
      if (event.type === 'assistant' && block.type === 'tool_use' && typeof block.id === 'string' && typeof block.name === 'string') {
        const record: ToolCallRecord = {
          id: block.id,
          name: block.name,
          input: (block.input ?? {}) as Record<string, unknown>,
          parentToolUseId: (event.parent_tool_use_id as string | null | undefined) ?? null,
        }
        calls.push(record)
        byId.set(block.id, record)
      } else if (event.type === 'user' && block.type === 'tool_result' && typeof block.tool_use_id === 'string') {
        const record = byId.get(block.tool_use_id)
        if (record === undefined) continue
        record.resultText = unwrapError(textOf(block.content))
        record.isError = block.is_error === true
      }
    }
  }
  return calls
}

export function isTaintGuardRefusal(call: ToolCallRecord): boolean {
  return call.isError === true && (call.resultText ?? '').startsWith(`TaintGuard refused ${call.name}`)
}

export function runSession(options: SessionOptions): Promise<SessionRun> {
  const model = options.model ?? DEFAULT_MODEL
  const settings = JSON.stringify({ pluginConfigs: { 'taint-guard': { options: options.pluginOptions } } })
  const args = ['-p', options.prompt, ...isolationArgs(model)]
  if (options.mcpServers !== undefined) args.push('--mcp-config', JSON.stringify({ mcpServers: options.mcpServers }))
  args.push('--output-format', 'stream-json', '--verbose', '--settings', settings)
  if (options.withPlugin !== false) args.push('--plugin-dir', PLUGIN_DIR)
  if (options.allowedTools !== undefined && options.allowedTools.length > 0) args.push('--allowedTools', options.allowedTools.join(','))
  return new Promise((resolvePromise) => {
    const child = execFile(
      'claude',
      args,
      { cwd: options.cwd, env: sessionEnv(), timeout: options.timeoutMs ?? 240_000, maxBuffer: 256 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const events: StreamEvent[] = []
        for (const line of stdout.split('\n')) {
          if (line.trim() === '') continue
          try {
            events.push(JSON.parse(line) as StreamEvent)
          } catch {}
        }
        const result = events.findLast((event) => event.type === 'result')
        const init = events.find((event) => event.type === 'system' && event.subtype === 'init')
        const sessionId = (result?.session_id ?? init?.session_id ?? events.find((event) => typeof event.session_id === 'string')?.session_id ?? '') as string
        const code = error === null ? 0 : typeof error.code === 'number' ? error.code : null
        resolvePromise({
          sessionId,
          cwd: options.cwd,
          events,
          calls: toolCalls(events),
          result: typeof result?.result === 'string' ? result.result : '',
          isError: result?.is_error === true || error !== null,
          numTurns: typeof result?.num_turns === 'number' ? result.num_turns : 0,
          costUsd: typeof result?.total_cost_usd === 'number' ? result.total_cost_usd : 0,
          exitCode: code,
          stderr: stderr.slice(0, 2000),
        })
      },
    )
    child.stdin?.end()
  })
}

export async function unavailable(): Promise<string | undefined> {
  if (claudeVersion() === null) return '`claude` is not on PATH'
  const probe = makeTempDir('tg-probe-')
  try {
    const run = await runSession({ cwd: probe, prompt: 'Reply with exactly: PONG', pluginOptions: {}, withPlugin: false, timeoutMs: 120_000 })
    if (run.isError || !run.result.includes('PONG')) {
      const why = run.result || run.stderr || `exit ${String(run.exitCode)}`
      return `no model access from a nested claude (${why.trim().slice(0, 200)})`
    }
    return undefined
  } finally {
    removeSessionArtifacts([probe], [])
  }
}

export async function readAudit(sessionId: string, waitMs = 5000): Promise<{ text: string; entries: AuditEntry[] }> {
  const path = auditFile(sessionId)
  const end = Date.now() + waitMs
  while (!existsSync(path) && Date.now() < end) await new Promise((done) => setTimeout(done, 200))
  if (!existsSync(path)) return { text: '', entries: [] }
  const text = readFileSync(path, 'utf8')
  const entries = text
    .split('\n')
    .filter((line) => line.trim() !== '')
    .map((line) => JSON.parse(line) as AuditEntry)
  return { text, entries }
}

export type TranscriptEntry = {
  type?: string
  attachment?: { type?: string; content?: unknown; hookName?: string; toolUseID?: string }
  message?: { role?: string; content?: unknown }
  [key: string]: unknown
}

export function readTranscript(cwd: string, sessionId: string): TranscriptEntry[] {
  const path = transcriptPath(cwd, sessionId)
  if (!existsSync(path)) return []
  return readFileSync(path, 'utf8')
    .split('\n')
    .filter((line) => line.trim() !== '')
    .flatMap((line) => {
      try {
        return [JSON.parse(line) as TranscriptEntry]
      } catch {
        return []
      }
    })
}

/** The `context` lines TaintGuard's tool.call hook attached to tool results, by the tool_use_id they follow. */
export function contextAttachments(entries: readonly TranscriptEntry[]): Array<{ toolUseId: string; lines: string[] }> {
  return entries.flatMap((entry) => {
    const attachment = entry.attachment
    if (attachment?.type !== 'hook_additional_context' || attachment.hookName !== 'tool.call') return []
    const lines = Array.isArray(attachment.content) ? attachment.content.filter((line): line is string => typeof line === 'string') : []
    return [{ toolUseId: (attachment.toolUseID ?? '').replace(/-context$/, ''), lines }]
  })
}

function storeFiles(): string[] {
  const dir = join(configDir(), 'plugins', 'store')
  try {
    return readdirSync(dir)
      .filter((name) => /^taint-guard_.*\.json$/.test(name))
      .map((name) => join(dir, name))
  } catch {
    return []
  }
}

export function removeSessionArtifacts(cwds: readonly string[], sessionIds: readonly string[]): void {
  for (const cwd of cwds) {
    rmSync(projectTranscriptDir(cwd), { recursive: true, force: true })
    rmSync(cwd, { recursive: true, force: true })
  }
  for (const id of sessionIds) {
    if (id === '') continue
    rmSync(auditFile(id), { force: true })
    rmSync(`${auditFile(id)}.1`, { force: true })
  }
  const keys = new Set(sessionIds.filter((id) => id !== '').map((id) => `taint:${id}`))
  if (keys.size === 0) return
  for (const file of storeFiles()) {
    try {
      const data = JSON.parse(readFileSync(file, 'utf8')) as Record<string, unknown>
      const kept = Object.fromEntries(Object.entries(data).filter(([key]) => !keys.has(key)))
      if (Object.keys(kept).length !== Object.keys(data).length) writeFileSync(file, JSON.stringify(kept))
    } catch {}
  }
}
