import type { ToolCall } from './types.ts'

export const SELF_PROTECT_RULE = 'builtin:self-protect'
export const SELF_PROTECT_REASON = 'TaintGuard does not let a tainted session change its own policy, settings or audit log.'

export type ProtectedPath = { path: string; isDir: boolean }

export type ProtectedPathsInput = {
  userPolicyPath: string
  managedPolicyPath: string | null
  cwd: string
  configDir: string | null
  home?: string
}

export type ProtectEnv = { cwd: string; home?: string }

export type SelfProtectHit = { rule: typeof SELF_PROTECT_RULE; reason: string }

const FILE_TOOLS = new Set(['Write', 'Edit', 'MultiEdit', 'NotebookEdit'])
const WRITE_VERBS = [
  'write',
  'edit',
  'create',
  'update',
  'move',
  'copy',
  'rename',
  'delete',
  'remove',
  'put',
  'save',
  'append',
  'patch',
  'set',
  'upload',
  'replace',
  'insert',
  'modify',
  'overwrite',
  'mkdir',
]
const BASH_MENTION = /taint-guard|\.claude(?![\w-])|settings\.local\.json/i
const DESTRUCTIVE_VERBS = ['move', 'rename', 'delete', 'remove', 'rmdir']
const DESTINATION_KEYS = ['path', 'file_path', 'filepath', 'filename', 'source', 'destination', 'dest', 'target', 'from', 'to', 'uri', 'directory', 'dir']
const MAX_STRINGS = 200
const MAX_DEPTH = 6

function trimSlashes(path: string): string {
  return path.replace(/\/+$/, '')
}

/** An absolute, lower-case, slash-separated form of `path`, with ~ expanded and . and .. collapsed. */
export function normalizePath(path: string, env: ProtectEnv): string {
  let p = path.trim().replace(/\\/g, '/')
  const home = env.home === undefined || env.home === '' ? undefined : trimSlashes(env.home.replace(/\\/g, '/'))
  if (home !== undefined && (p === '~' || p.startsWith('~/'))) p = home + p.slice(1)
  const drive = /^[a-z]:(?=\/|$)/i.exec(p)?.[0] ?? ''
  if (drive === '' && !p.startsWith('/')) p = `${trimSlashes(env.cwd.replace(/\\/g, '/'))}/${p}`
  const cwdDrive = drive === '' ? (/^[a-z]:(?=\/|$)/i.exec(p)?.[0] ?? '') : drive
  const segments: string[] = []
  for (const segment of p.slice(cwdDrive.length).split('/')) {
    if (segment === '' || segment === '.') continue
    if (segment === '..') segments.pop()
    else segments.push(segment)
  }
  return `${cwdDrive}/${segments.join('/')}`.toLowerCase()
}

/** The files and directories TaintGuard keeps a tainted session from writing. */
export function protectedPaths(input: ProtectedPathsInput): ProtectedPath[] {
  const env: ProtectEnv = input.home === undefined ? { cwd: input.cwd } : { cwd: input.cwd, home: input.home }
  const files = [input.userPolicyPath, '.claude/taint-guard.json', '.claude/settings.json', '.claude/settings.local.json']
  if (input.managedPolicyPath !== null) files.push(input.managedPolicyPath)
  const dirs: string[] = []
  if (input.configDir !== null) {
    const config = trimSlashes(input.configDir.replace(/\\/g, '/'))
    files.push(`${config}/settings.json`, `${config}/settings.local.json`)
    dirs.push(`${config}/taint-guard`, `${config}/plugins`)
  }
  const out: ProtectedPath[] = []
  const seen = new Set<string>()
  const add = (raw: string, isDir: boolean): void => {
    const path = normalizePath(raw, env)
    const key = `${isDir ? 'd' : 'f'}${path}`
    if (seen.has(key)) return
    seen.add(key)
    out.push({ path, isDir })
  }
  for (const file of files) add(file, false)
  for (const dir of dirs) add(dir, true)
  return out
}

function isProtected(raw: string, paths: readonly ProtectedPath[], env: ProtectEnv, ancestors = false): boolean {
  if (raw.trim() === '') return false
  const path = normalizePath(raw, env)
  const isAncestor = (p: ProtectedPath): boolean => ancestors && (path === '/' || p.path.startsWith(`${path}/`))
  return paths.some((p) => path === p.path || (p.isDir && path.startsWith(`${p.path}/`)) || isAncestor(p))
}

function words(name: string): string[] {
  return name
    .replace(/([a-z0-9])([A-Z])/g, '$1_$2')
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((word) => word !== '')
}

function hasVerb(tool: string, verbs: readonly string[]): boolean {
  const name = tool.split('__').slice(2).join('__')
  return words(name).some((word) => verbs.some((verb) => word === verb || (verb.length >= 4 && word.startsWith(verb))))
}

/** Whether an MCP tool's own name (after `mcp__<server>__`) carries a write verb. */
export function hasWriteVerb(tool: string): boolean {
  return hasVerb(tool, WRITE_VERBS)
}

/** Collects string values; returns false when the limits cut the scan short. */
function strings(value: unknown, out: string[], depth: number): boolean {
  if (typeof value === 'string') {
    if (out.length >= MAX_STRINGS) return false
    out.push(value)
    return true
  }
  if (typeof value !== 'object' || value === null) return true
  if (depth >= MAX_DEPTH) return false
  const items = Array.isArray(value) ? value : Object.values(value)
  return items.every((item) => strings(item, out, depth + 1))
}

/** The built-in rule's verdict on a call that would change TaintGuard's policy, settings or audit log, or null. */
export function selfProtect(call: ToolCall, paths: readonly ProtectedPath[], env: ProtectEnv): SelfProtectHit | null {
  const hit: SelfProtectHit = { rule: SELF_PROTECT_RULE, reason: SELF_PROTECT_REASON }
  const args = call.args
  if (FILE_TOOLS.has(call.tool)) {
    for (const key of ['file_path', 'notebook_path']) {
      const value = args[key]
      if (typeof value === 'string' && isProtected(value, paths, env)) return hit
    }
    return null
  }
  if (call.tool === 'Bash') return typeof args.command === 'string' && BASH_MENTION.test(args.command) ? hit : null
  if (call.tool.startsWith('mcp__') && hasWriteVerb(call.tool)) {
    const ancestors = hasVerb(call.tool, DESTRUCTIVE_VERBS)
    const named = DESTINATION_KEYS.map((key) => args[key]).filter((value): value is string => typeof value === 'string')
    if (named.some((value) => isProtected(value, paths, env, ancestors))) return hit
    const found: string[] = []
    const isComplete = strings(args, found, 0)
    if (!isComplete) return hit
    return found.some((value) => isProtected(value, paths, env, ancestors)) ? hit : null
  }
  return null
}
