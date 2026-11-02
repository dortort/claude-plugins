import type { PluginOptions } from 'claude-code'
import type { TaintRecord } from '../src/state.ts'
import { addFiring } from '../src/state.ts'
import type { ActiveSummary, Firing, StoredTaint, TaintSnapshot } from '../src/types.ts'

export const DEFAULT_USER_POLICY = '~/.claude/taint-guard.json'

export const USAGE =
  'Usage: /taintguard [explain <tool> [json args] | tools | clear [label…] | reload | audit]'

export const EMPTY_SUMMARY: ActiveSummary = { denied: [], asked: [], deniedPatterns: [], askedPatterns: [] }

export type TaintGuardOptions = {
  enabled: boolean
  preset: unknown
  userPolicyPath: string
  managedPolicyPath: unknown
  showBand: boolean
  auditLog: boolean
  auditArguments: boolean
}

export function readOptions(options: PluginOptions): TaintGuardOptions {
  const userPath = options.userPolicyPath
  return {
    enabled: options.enabled !== false,
    preset: options.preset,
    userPolicyPath: typeof userPath === 'string' && userPath.trim() !== '' ? userPath : DEFAULT_USER_POLICY,
    managedPolicyPath: options.managedPolicyPath,
    showBand: options.showBand !== false,
    auditLog: options.auditLog !== false,
    auditArguments: options.auditArguments === true,
  }
}

export function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

export function splitCommand(args: string): { sub: string; rest: string } {
  const match = /^(\S*)\s*([\s\S]*)$/.exec(args.trim())
  return { sub: (match?.[1] ?? '').toLowerCase(), rest: match?.[2] ?? '' }
}

/** Both snapshots' labels: `a`'s firings first, then `b`'s, then a carry firing for any label left unexplained. */
export function unionTaint(a: TaintSnapshot, b: TaintSnapshot, at: number): TaintSnapshot {
  let next = a
  for (const firing of b.firedBy) next = addFiring(next, firing).next
  const missing = b.labels.filter((label) => !next.labels.includes(label))
  if (missing.length > 0) next = addFiring(next, { rule: 'carry', tool: '(carried taint)', labels: missing, at }).next
  return { ...next, blockedCount: Math.max(a.blockedCount, b.blockedCount) }
}

export function mergeStored(own: StoredTaint | null, parent: StoredTaint | null): StoredTaint | null {
  if (own === null) return parent
  if (parent === null) return own
  const firedBy: Firing[] = [...own.firedBy, ...parent.firedBy]
  const merged: StoredTaint = {
    labels: [...new Set([...own.labels, ...parent.labels])].sort(),
    firedBy,
    savedAt: Math.max(own.savedAt, parent.savedAt),
  }
  const cut = own.clearedThrough ?? parent.clearedThrough
  if (cut !== undefined) merged.clearedThrough = cut
  return merged
}

export function rebuildDetail(origin: string, records: readonly TaintRecord[], truncated: boolean): string {
  const parts = [`rebuilt after ${origin}`]
  if (records.length > 0) parts.push(`records: ${records.map((record) => JSON.stringify(record.excerpt)).join(', ')}`)
  if (truncated) parts.push('history may be cut')
  return parts.join('; ')
}

/** Whether a background task started before the first firing; an unknown start counts as before. */
export function startedBefore(starts: ReadonlyMap<string, number>, command: string | undefined, firstAt: number | undefined): boolean {
  if (firstAt === undefined || command === undefined) return true
  const start = starts.get(command)
  return start === undefined || start < firstAt
}
