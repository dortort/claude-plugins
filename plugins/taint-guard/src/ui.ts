import type { ActiveSummary, AuditEntry, SinkDecision, TaintSnapshot, Timing } from './types.ts'

export const ASK_ALLOW = 'Allow once'
export const ASK_REFUSE = 'Refuse'

const NEXT_STEP =
  'Do not retry this call or reach the same result through another tool. Continue with allowed tools, or tell the user what you need run and why.'

type DenyInput = {
  tool: string
  reason: string
  labels: readonly string[]
  fromTools: readonly string[]
  rule: string
  lockdown?: string | null
}

type LayerLine = { layer: string; path: string | null; status: string; rules: number; error?: string }
type SinkLine = { id: string; action: string; reason: string }
type BackgroundLine = { id: string; type: string; description: string; command?: string }

/** Labels sorted and comma-separated. */
export function labelList(labels: readonly string[]): string {
  return [...labels].sort().join(', ')
}

/** Distinct tools that fired sources, in firing order, at most `max`. */
export function sourceTools(taint: TaintSnapshot, max = 3): string[] {
  const out: string[] = []
  for (const firing of taint.firedBy) {
    if (out.length >= max) break
    if (!out.includes(firing.tool)) out.push(firing.tool)
  }
  return out
}

function oneLine(text: string, max: number): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  if (flat.length <= max) return flat
  return `${flat.slice(0, Math.max(0, max - 1)).trimEnd()}…`
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value : undefined
}

function compactJson(args: Readonly<Record<string, unknown>>): string {
  if (Object.keys(args).length === 0) return ''
  try {
    return JSON.stringify(args) ?? ''
  } catch {
    return '[unprintable arguments]'
  }
}

function pickedText(tool: string, args: Readonly<Record<string, unknown>>): string | undefined {
  switch (tool) {
    case 'Bash':
      return str(args.command)
    case 'WebFetch':
      return str(args.url)
    case 'WebSearch':
      return str(args.query)
    case 'Read':
    case 'Write':
    case 'Edit':
    case 'NotebookEdit':
      return str(args.file_path) ?? str(args.notebook_path)
    case 'Grep':
    case 'Glob': {
      const pattern = str(args.pattern)
      const path = str(args.path)
      if (pattern === undefined) return undefined
      return path === undefined ? pattern : `${pattern} in ${path}`
    }
    default:
      return undefined
  }
}

/** A one-line summary of a call's arguments, cut with '…' at `max` characters. */
export function argSummary(tool: string, args: Readonly<Record<string, unknown>>, max = 120): string {
  return oneLine(pickedText(tool, args) ?? compactJson(args), max)
}

/** Argument keys that usually say where data goes, listed first in an ask. */
export const DESTINATION_KEYS: readonly string[] = [
  'url',
  'uri',
  'channel',
  'channel_id',
  'to',
  'recipient',
  'recipients',
  'email',
  'repo',
  'owner',
  'path',
  'file_path',
  'command',
  'query',
]

export const ASK_SUMMARY_MAX = 600
const ASK_HEAD = 300
const ASK_TAIL = 280

function destinationFirst(args: Readonly<Record<string, unknown>>): Record<string, unknown> {
  const out: Record<string, unknown> = {}
  for (const key of DESTINATION_KEYS) if (Object.hasOwn(args, key)) out[key] = args[key]
  for (const [key, value] of Object.entries(args)) if (!Object.hasOwn(out, key)) out[key] = value
  return out
}

/** The argument summary an ask shows: destination keys first, and over 600 characters the head and the tail. */
export function askSummary(tool: string, args: Readonly<Record<string, unknown>>): string {
  const picked = tool.startsWith('mcp__') ? undefined : pickedText(tool, args)
  const flat = (picked ?? compactJson(destinationFirst(args))).replace(/\s+/g, ' ').trim()
  if (flat.length <= ASK_SUMMARY_MAX) return flat
  return `${flat.slice(0, ASK_HEAD).trimEnd()} … ${flat.slice(-ASK_TAIL).trimStart()}`
}

/** A sink's reason as Claude and the user see it: a repository's own words are marked as such. */
export function sinkReason(reason: string, trusted: boolean): string {
  return trusted || reason === '' ? reason : `(repository policy) ${reason}`
}

function joinSentences(...parts: string[]): string {
  return parts.filter((part) => part.trim() !== '').join(' ')
}

function labelsLine(input: DenyInput): string {
  if (input.lockdown) return `Active labels: all (TaintGuard is in lockdown: ${input.lockdown}). Rule: ${input.rule}.`
  const labels = input.labels.length > 0 ? labelList(input.labels) : 'none'
  const from = input.fromTools.length > 0 ? ` (from ${input.fromTools.join(', ')})` : ''
  return `Active labels: ${labels}${from}. Rule: ${input.rule}.`
}

/** The three-line tool result Claude reads when a call is denied. */
export function denyText(input: DenyInput): string {
  return [joinSentences(`TaintGuard refused ${input.tool}.`, input.reason), labelsLine(input), NEXT_STEP].join('\n')
}

/** The deny text for an ask the user refused. */
export function askRefusedText(input: DenyInput): string {
  return [
    joinSentences(`TaintGuard refused ${input.tool}: the user did not approve it.`, input.reason),
    labelsLine(input),
    NEXT_STEP,
  ].join('\n')
}

/** The deny text when the guard failed and the fail-safe refused the call. */
export function failureDenyText(tool: string, why: string): string {
  return [
    `TaintGuard refused ${tool}. TaintGuard could not finish checking this call (${why}) and it may match a rule that blocks it.`,
    NEXT_STEP,
  ].join('\n')
}

/** The question put to the user for an ask sink. */
export function askQuestion(input: { tool: string; argSummary: string; reason: string; labels: readonly string[] }): string {
  const holds = input.labels.length > 0 ? `This session holds ${labelList(input.labels)} content.` : ''
  const call = input.argSummary === '' ? input.tool : `${input.tool} (${input.argSummary})`
  return joinSentences(input.reason, holds, `Allow ${call} once?`)
}

/** Comma lists of refused and asked tools; a raw /regex/ or prefix… pattern reads "tools matching <pattern>". */
export function toolsSentence(summary: ActiveSummary): { refused: string; asks: string } {
  const isRaw = (pattern: string): boolean => pattern.startsWith('/') || pattern.endsWith('…')
  const render = (names: readonly string[], patterns: readonly string[]): string =>
    [...names, ...patterns.map((pattern) => (isRaw(pattern) ? `tools matching ${pattern}` : pattern))].join(', ')
  return {
    refused: render(summary.denied, summary.deniedPatterns),
    asks: render(summary.asked, summary.askedPatterns),
  }
}

function fromPart(fromTools: readonly string[]): string {
  return fromTools.length > 0 ? ` (from ${fromTools.join(', ')})` : ''
}

/** The context line attached to a source's result when the taint set grew. */
export function taintContextLine(input: {
  labels: readonly string[]
  fromTools: readonly string[]
  summary: ActiveSummary
}): string {
  const { refused, asks } = toolsSentence(input.summary)
  const parts = [`TaintGuard: this session now holds ${labelList(input.labels)} content${fromPart(input.fromTools)}.`]
  if (refused !== '') parts.push(`From now on these tools will be refused: ${refused}.`)
  if (asks !== '') parts.push(`These need user approval: ${asks}.`)
  if (refused === '' && asks === '') parts.push('No tool is blocked by this yet.')
  return parts.join(' ')
}

/** The context line added on each prompt while tainted or in lockdown. */
export function promptContextLine(input: {
  labels: readonly string[]
  fromTools: readonly string[]
  summary: ActiveSummary
  lockdown: string | null
}): string {
  const { refused, asks } = toolsSentence(input.summary)
  const parts = [
    input.lockdown
      ? `TaintGuard is in lockdown (${input.lockdown}): every rule is active as if all labels were present.`
      : `TaintGuard: this session holds ${labelList(input.labels)} content${fromPart(input.fromTools)}.`,
  ]
  if (refused !== '') parts.push(`These tools are refused: ${refused}.`)
  if (asks !== '') parts.push(`These need user approval: ${asks}.`)
  parts.push(
    refused === '' && asks === '' ? 'No tool is blocked by this yet.' : 'Do not try to reach a refused result through another tool.',
  )
  return parts.join(' ')
}

function pad2(n: number): string {
  return String(n).padStart(2, '0')
}

/** Local HH:MM. */
export function localTime(ms: number): string {
  const date = new Date(ms)
  return `${pad2(date.getHours())}:${pad2(date.getMinutes())}`
}

function bandList(names: readonly string[], patterns: readonly string[]): string {
  const listed = names.filter((name) => !name.startsWith('mcp__'))
  const mcp = names.length - listed.length
  const items = [...listed]
  if (mcp > 0) items.push(`${mcp} MCP ${mcp === 1 ? 'tool' : 'tools'}`)
  if (items.length === 0 && patterns.length > 0) items.push('rules on other tools')
  return items.join(', ')
}

/** The one-line band above the prompt, or null while the session is clean. */
export function bandText(input: {
  taint: TaintSnapshot
  lockdown: string | null
  summary: ActiveSummary
  formatTime?: (ms: number) => string
}): string | null {
  if (input.lockdown) return `TaintGuard · LOCKDOWN: ${input.lockdown} · all sinks active`
  if (input.taint.labels.length === 0) return null
  const formatTime = input.formatTime ?? localTime
  const first = input.taint.firedBy[0]
  const origin = first ? ` (${first.tool}, ${formatTime(first.at)})` : ''
  const segments = [`TaintGuard`, `tainted: ${labelList(input.taint.labels)}${origin}`]
  const blocked = bandList(input.summary.denied, input.summary.deniedPatterns)
  const asks = bandList(input.summary.asked, input.summary.askedPatterns)
  if (blocked !== '') segments.push(`blocked: ${blocked}`)
  if (asks !== '') segments.push(`asks: ${asks}`)
  segments.push('/taintguard')
  return segments.join(' · ')
}

/** The transcript line for one refusal. */
export function refusalLogLine(tool: string, rule: string): string {
  return `TaintGuard refused ${tool} (${rule})`
}

/** The transcript line for repeated refusals of one tool in a turn. */
export function refusalCountLine(tool: string, count: number): string {
  return `TaintGuard refused ${tool} ${count} times this turn`
}

function section(title: string, lines: readonly string[]): string {
  return [title, ...(lines.length > 0 ? lines.map((line) => `  ${line}`) : ['  none'])].join('\n')
}

/** The /taintguard status report. */
export function statusReport(input: {
  taint: TaintSnapshot
  lockdown: string | null
  enabled: boolean
  preset: string
  layers: ReadonlyArray<LayerLine>
  warnings: readonly string[]
  activeSinks: ReadonlyArray<SinkLine>
  summary: ActiveSummary
  background: ReadonlyArray<BackgroundLine>
  formatTime?: (ms: number) => string
}): string {
  const formatTime = input.formatTime ?? localTime
  const heading = !input.enabled
    ? 'TaintGuard: off'
    : input.lockdown
      ? `TaintGuard: LOCKDOWN — ${input.lockdown}`
      : input.taint.labels.length > 0
        ? `TaintGuard: tainted (${labelList(input.taint.labels)})`
        : 'TaintGuard: clean'

  const labelLines = [...input.taint.labels].sort().map((label) => {
    const firings = input.taint.firedBy.filter((firing) => firing.labels.includes(label))
    if (firings.length === 0) return `${label}: no record of the call that added it`
    const origins = firings.map((firing) => {
      const agent = firing.agentId ? ` (subagent ${firing.agentId})` : ''
      return `${firing.rule} via ${firing.tool}${agent} at ${formatTime(firing.at)}`
    })
    return `${label}: ${origins.join('; ')}`
  })

  const { refused, asks } = toolsSentence(input.summary)
  const layerLines = input.layers.map((layer) => {
    const rules = `${layer.rules} ${layer.rules === 1 ? 'rule' : 'rules'}`
    const error = layer.error ? `, error: ${layer.error}` : ''
    return `${layer.layer}: ${layer.status}, ${rules}, ${layer.path ?? 'no file'}${error}`
  })
  const backgroundLines = input.background.map((task) => {
    const command = task.command ? `: ${task.command}` : ''
    return `${task.id} (${task.type}) ${task.description}${command}`
  })

  return [
    heading,
    section('Labels', labelLines),
    section(
      'Active rules',
      input.activeSinks.map((sink) => joinSentences(`${sink.id} (${sink.action}):`, sink.reason)),
    ),
    `Refused calls: ${input.taint.blockedCount}`,
    [`Refused now: ${refused || 'none'}`, `Needs approval: ${asks || 'none'}`].join('\n'),
    section(`Policy layers (preset: ${input.preset})`, layerLines),
    section('Warnings', input.warnings),
    section('Background tasks started before taint', backgroundLines),
  ].join('\n\n')
}

/** The /taintguard explain dry-run report. */
export function explainReport(input: {
  tool: string
  args: Readonly<Record<string, unknown>>
  decision: SinkDecision
  wouldTaint: ReadonlyArray<{ id: string; on: Timing; taints: readonly string[] }>
  labels: readonly string[]
  lockdown: string | null
}): string {
  const summary = argSummary(input.tool, input.args)
  const lines = [`TaintGuard explain: ${input.tool}${summary === '' ? '' : ` (${summary})`}`]
  const primary = input.decision.primary ?? input.decision.matches[0]
  const rule = primary?.sink.id ?? 'unknown rule'
  const reason = primary?.sink.reason ?? ''
  switch (input.decision.action) {
    case 'allow':
      lines.push('Would be allowed')
      break
    case 'deny':
      lines.push(`Would be refused by ${rule}${reason === '' ? '' : `: ${reason}`}`)
      break
    case 'ask':
      lines.push(`Would ask the user (${rule})${reason === '' ? '' : `: ${reason}`}`)
      break
    case 'audit':
      lines.push(`Would be allowed; audit-only match: ${rule}`)
      break
  }
  const others = input.decision.matches.filter((match) => match !== primary)
  if (others.length > 0) {
    lines.push(`Also matches: ${others.map((match) => `${match.sink.id} (${match.action})`).join(', ')}`)
  }
  lines.push(
    input.lockdown
      ? `Current labels: all (TaintGuard is in lockdown: ${input.lockdown})`
      : `Current labels: ${input.labels.length > 0 ? labelList(input.labels) : 'none'}`,
  )
  if (input.wouldTaint.length === 0) {
    lines.push('Sources that would fire: none')
  } else {
    lines.push('Sources that would fire:')
    for (const source of input.wouldTaint) {
      lines.push(`  ${source.id} (on ${source.on}): ${labelList(source.taints)}`)
    }
  }
  return lines.join('\n')
}

/** The reply after a successful declassification; `arrived` names labels added while the confirmation was open. */
export function clearedText(removed: readonly string[], remaining: readonly string[], arrived: readonly string[] = []): string {
  if (removed.length === 0) return nothingToClearText()
  const rest = remaining.length > 0 ? `Still present: ${labelList(remaining)}.` : 'The session is clean.'
  const kept = arrived.length > 0 ? ` Kept ${labelList(arrived)}, which arrived while you were confirming.` : ''
  return `TaintGuard cleared ${labelList(removed)}. ${rest}${kept}`
}

/** The reply when policy forbids declassification. */
export function clearRefusedText(policyFrom: string): string {
  return `Declassification is disabled by the ${policyFrom} policy (userDeclassify: never).`
}

/** The reply while the taint set is not yet rebuilt, so what a clear would remove is not known. */
export function clearPendingText(): string {
  return 'TaintGuard has not yet rebuilt the taint set for this session, so nothing can be cleared now; labels unchanged. Try again shortly.'
}

/** The reply when the user declines the confirmation. */
export function clearDeclinedText(): string {
  return 'Declassification cancelled; labels unchanged.'
}

/** The reply when no requested label is present. */
export function nothingToClearText(): string {
  return 'TaintGuard: nothing to clear; no matching label is present.'
}

/** The /taintguard audit report: the log path and one line per entry. */
export function auditReport(path: string, entries: readonly AuditEntry[]): string {
  const lines = [`Audit log: ${path}`]
  if (entries.length === 0) lines.push('  no entries yet')
  for (const entry of entries) {
    const fields = [entry.ts, entry.event]
    if (entry.tool) fields.push(entry.tool)
    if (entry.rule) fields.push(entry.rule)
    if (entry.labels && entry.labels.length > 0) fields.push(`[${labelList(entry.labels)}]`)
    if (entry.detail) fields.push(oneLine(entry.detail, 200))
    lines.push(`  ${fields.join('  ')}`)
  }
  return lines.join('\n')
}
