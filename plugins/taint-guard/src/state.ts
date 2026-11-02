import type { Firing, MessageLike, StoredTaint, TaintSnapshot, Timing, ToolCall, UnknownHistory } from './types.ts'

export const EMPTY_TAINT: TaintSnapshot = Object.freeze({
  labels: Object.freeze([]) as unknown as string[],
  firedBy: Object.freeze([]) as unknown as Firing[],
  blockedCount: 0,
})

export const FIRED_BY_CAP = 100
export const RECORD_PREFIX = 'TaintGuard taint record v1: labels='
export const OWN_DENIAL_PREFIX = 'TaintGuard refused '
export const STORE_PREFIX = 'taint:'
export const STORE_MAX_AGE_MS = 14 * 24 * 60 * 60 * 1000

const LABEL_NAME = /^[A-Za-z0-9-]{1,32}$/
const RECORD_VALUE = /^[A-Za-z0-9-]+(?:[ \t]*,[ \t]*[A-Za-z0-9-]+)*/
const EXCERPT_MAX = 120

export type TaintRecord = { labels: string[]; excerpt: string }

export type SourceMatch = { id: string; taints: readonly string[] }

export type RebuildInput = {
  messages: readonly MessageLike[]
  agentMessages?: ReadonlyArray<readonly MessageLike[]>
  match: (call: ToolCall, timing: Timing) => ReadonlyArray<SourceMatch>
  declaredLabels: readonly string[]
  onUnknownHistory: UnknownHistory
  storeCopy: StoredTaint | null
  historyLimit: number
  at: number
  base?: TaintSnapshot
}

export type RebuildResult = {
  snapshot: TaintSnapshot
  records: TaintRecord[]
  truncated: boolean
  added: string[]
}

function copyFiring(f: Firing): Firing {
  const out: Firing = { rule: f.rule, tool: f.tool, labels: [...f.labels], at: f.at }
  if (f.agentId !== undefined) out.agentId = f.agentId
  if (f.toolUseId !== undefined) out.toolUseId = f.toolUseId
  return out
}

function sortedUnique(labels: Iterable<string>): string[] {
  return [...new Set(labels)].sort()
}

/** Adds a firing's labels; the firing is recorded only when it added something. */
export function addFiring(snapshot: TaintSnapshot, firing: Firing): { next: TaintSnapshot; added: string[] } {
  const have = new Set(snapshot.labels)
  const added = sortedUnique(firing.labels.filter((l) => !have.has(l)))
  if (added.length === 0) return { next: snapshot, added }
  const firedBy = [...snapshot.firedBy]
  if (firedBy.length < FIRED_BY_CAP) firedBy.push({ ...copyFiring(firing), labels: added })
  return {
    next: { labels: sortedUnique([...snapshot.labels, ...added]), firedBy, blockedCount: snapshot.blockedCount },
    added,
  }
}

/** Removes the given labels, or every label when none are given. */
export function removeLabels(
  snapshot: TaintSnapshot,
  labels?: readonly string[],
): { next: TaintSnapshot; removed: string[] } {
  const target = labels === undefined ? new Set(snapshot.labels) : new Set(labels)
  const removed = snapshot.labels.filter((l) => target.has(l))
  if (removed.length === 0) return { next: snapshot, removed }
  const gone = new Set(removed)
  const firedBy: Firing[] = []
  for (const f of snapshot.firedBy) {
    const kept = f.labels.filter((l) => !gone.has(l))
    if (kept.length > 0) firedBy.push({ ...copyFiring(f), labels: kept })
  }
  return {
    next: { labels: snapshot.labels.filter((l) => !gone.has(l)), firedBy, blockedCount: snapshot.blockedCount },
    removed: [...removed].sort(),
  }
}

export function countBlocked(snapshot: TaintSnapshot): TaintSnapshot {
  return { labels: [...snapshot.labels], firedBy: snapshot.firedBy.map(copyFiring), blockedCount: snapshot.blockedCount + 1 }
}

/** Whether two label lists hold the same set of names. */
export function sameLabels(a: readonly string[], b: readonly string[]): boolean {
  const sa = new Set(a)
  const sb = new Set(b)
  if (sa.size !== sb.size) return false
  for (const l of sa) if (!sb.has(l)) return false
  return true
}

export function formatRecord(labels: readonly string[]): string {
  return RECORD_PREFIX + sortedUnique(labels).join(',')
}

/** Every taint record in the text, in order of appearance. */
export function findRecords(text: string): TaintRecord[] {
  const out: TaintRecord[] = []
  let from = 0
  for (;;) {
    const at = text.indexOf(RECORD_PREFIX, from)
    if (at < 0) return out
    const valueStart = at + RECORD_PREFIX.length
    const value = RECORD_VALUE.exec(text.slice(valueStart, valueStart + 4096))?.[0] ?? ''
    const labels = sortedUnique(value.split(',').map((s) => s.trim()).filter((s) => LABEL_NAME.test(s)))
    const lineStart = text.lastIndexOf('\n', at) + 1
    const nl = text.indexOf('\n', at)
    const lineEnd = nl < 0 ? text.length : nl
    let excerpt = text.slice(lineStart, lineEnd).trim()
    if (excerpt.length > EXCERPT_MAX) excerpt = text.slice(at, lineEnd).trim()
    out.push({ labels, excerpt: excerpt.slice(0, EXCERPT_MAX) })
    from = valueStart
  }
}

export function compactInstructions(existing: string | undefined, labels: readonly string[]): string {
  const ask =
    'TaintGuard: this conversation holds tainted content. Copy the following line verbatim, on a line of its own, into the summary:\n' +
    formatRecord(labels)
  return existing ? `${existing}\n\n${ask}` : ask
}

export function isOwnDenial(text: string | undefined): boolean {
  return typeof text === 'string' && text.startsWith(OWN_DENIAL_PREFIX)
}

function cutAfter(messages: readonly MessageLike[], toolUseId: string | undefined): number {
  if (toolUseId === undefined) return 0
  const at = messages.findIndex((m) => m.toolUses.some((u) => u.tool_use_id === toolUseId))
  return at === -1 ? 0 : at + 1
}

/** Rebuilds the taint set from history, the store copy and taint records; it only ever adds labels. */
export function rebuild(input: RebuildInput): RebuildResult {
  const base = input.base ?? EMPTY_TAINT
  const labels = new Set(base.labels)
  const firedBy = base.firedBy.map(copyFiring)
  const declared = new Set(input.declaredLabels)
  const records: TaintRecord[] = []
  const at = input.at

  const fire = (rule: string, tool: string, taints: Iterable<string>, extra?: { agentId?: string; toolUseId?: string }) => {
    const added: string[] = []
    for (const l of taints) {
      if (!labels.has(l)) {
        labels.add(l)
        added.push(l)
      }
    }
    if (added.length === 0 || firedBy.length >= FIRED_BY_CAP) return
    const f: Firing = { rule, tool, labels: sortedUnique(added), at }
    if (extra?.agentId !== undefined) f.agentId = extra.agentId
    if (extra?.toolUseId !== undefined) f.toolUseId = extra.toolUseId
    firedBy.push(f)
  }

  if (input.storeCopy) fire('store', '(saved taint)', input.storeCopy.labels)

  const cut = cutAfter(input.messages, input.storeCopy?.clearedThrough)
  const conversations: Array<readonly MessageLike[]> = [input.messages.slice(cut), ...(input.agentMessages ?? [])]
  for (const messages of conversations) {
    for (const message of messages) {
      for (const use of message.toolUses) {
        if (use.isError === true && isOwnDenial(use.text)) continue
        const call: ToolCall = { tool: use.tool, args: use.input, toolUseId: use.tool_use_id }
        if (use.agentId !== undefined) call.agentId = use.agentId
        const extra = { agentId: use.agentId, toolUseId: use.tool_use_id }
        for (const source of input.match(call, 'attempt')) fire(source.id, use.tool, source.taints, extra)
        if (use.text !== undefined && use.isError !== true) {
          for (const source of input.match(call, 'success')) fire(source.id, use.tool, source.taints, extra)
        }
      }
    }
  }

  const scan = (text: string | undefined) => {
    if (typeof text !== 'string' || !text.includes(RECORD_PREFIX)) return
    for (const record of findRecords(text)) {
      records.push(record)
      fire('record', '(taint record)', record.labels.filter((l) => declared.has(l)))
    }
  }
  for (const messages of conversations) {
    for (const message of messages) {
      scan(message.text)
      for (const use of message.toolUses) scan(use.text)
      for (const result of message.toolResults ?? []) scan(result.text)
    }
  }

  const truncated = input.messages.length >= input.historyLimit
  if (truncated && input.onUnknownHistory === 'assume-tainted') fire('history-cut', '(history cut)', input.declaredLabels)

  const baseLabels = new Set(base.labels)
  const finalLabels = [...labels].sort()
  return {
    snapshot: { labels: finalLabels, firedBy, blockedCount: base.blockedCount },
    records,
    truncated,
    added: finalLabels.filter((l) => !baseLabels.has(l)),
  }
}

export function storeKey(sessionId: string): string {
  return STORE_PREFIX + sessionId
}

export function toStored(snapshot: TaintSnapshot, at: number, clearedThrough?: string): StoredTaint {
  const stored: StoredTaint = { labels: [...snapshot.labels], firedBy: snapshot.firedBy.map(copyFiring), savedAt: at }
  if (clearedThrough !== undefined) stored.clearedThrough = clearedThrough
  return stored
}

/** The id of the newest tool use in the conversation, the cut point a declassification records. */
export function lastToolUseId(messages: readonly MessageLike[]): string | undefined {
  for (let i = messages.length - 1; i >= 0; i -= 1) {
    const uses = messages[i]?.toolUses ?? []
    const last = uses[uses.length - 1]
    if (last) return last.tool_use_id
  }
  return undefined
}

function isStringArray(value: unknown): value is string[] {
  return Array.isArray(value) && value.every((v) => typeof v === 'string')
}

function parseFiring(value: unknown): Firing | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const v = value as Record<string, unknown>
  if (typeof v.rule !== 'string' || typeof v.tool !== 'string' || !isStringArray(v.labels)) return null
  if (typeof v.at !== 'number' || !Number.isFinite(v.at)) return null
  if (v.agentId !== undefined && typeof v.agentId !== 'string') return null
  if (v.toolUseId !== undefined && typeof v.toolUseId !== 'string') return null
  return copyFiring(v as unknown as Firing)
}

/** A validated copy of a `$.store` value, or null when it is not a StoredTaint. */
export function parseStored(value: unknown): StoredTaint | null {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return null
  const v = value as Record<string, unknown>
  if (!isStringArray(v.labels) || !Array.isArray(v.firedBy)) return null
  if (typeof v.savedAt !== 'number' || !Number.isFinite(v.savedAt)) return null
  const firedBy: Firing[] = []
  for (const f of v.firedBy) {
    const parsed = parseFiring(f)
    if (!parsed) return null
    firedBy.push(parsed)
  }
  if (v.clearedThrough !== undefined && typeof v.clearedThrough !== 'string') return null
  const stored: StoredTaint = { labels: [...v.labels], firedBy, savedAt: v.savedAt }
  if (typeof v.clearedThrough === 'string') stored.clearedThrough = v.clearedThrough
  return stored
}

/** Store keys of taint copies that are unreadable or older than maxAgeMs. */
export function staleStoreKeys(
  entries: ReadonlyArray<readonly [string, unknown]>,
  now: number,
  maxAgeMs: number = STORE_MAX_AGE_MS,
): string[] {
  const out: string[] = []
  for (const [key, value] of entries) {
    if (!key.startsWith(STORE_PREFIX)) continue
    const stored = parseStored(value)
    if (!stored || now - stored.savedAt > maxAgeMs) out.push(key)
  }
  return out
}
