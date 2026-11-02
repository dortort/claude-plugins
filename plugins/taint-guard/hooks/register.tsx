import { atom, read, update } from 'claude-code'
import type { CommandRunInput, EngineInterface, Register, SessionMessage, ToolCallResult } from 'claude-code'
import {
  argsSnippet,
  auditPath,
  callArguments,
  canonicalJson,
  configDirFrom,
  createAuditLog,
  generateKeyHex,
  hmacHex,
  type AuditLog,
} from '../src/audit.ts'
import { parseClearArgs, parseExplainArgs, toolsReport } from '../src/inventory.ts'
import { effectivePreset, expandHome, ignoredManagedPathWarning, managedOptionsFrom } from '../src/managed.ts'
import { activeSummary, allLabels, evaluateSinks, failSafeDecision, isSinkActive, loadPolicy, matchSources } from '../src/policy.ts'
import { PRESETS, classifyTool, describePattern } from '../src/presets.ts'
import {
  EMPTY_TAINT,
  addFiring,
  compactInstructions,
  countBlocked,
  formatRecord,
  lastToolUseId,
  parseStored,
  rebuild,
  removeLabels,
  staleStoreKeys,
  storeKey,
  toStored,
  type RebuildResult,
} from '../src/state.ts'
import type {
  ActiveSummary,
  AuditEntry,
  AuditEvent,
  CompiledPolicy,
  CompiledSource,
  Firing,
  LayerText,
  LoadedPolicy,
  PresetName,
  StoredTaint,
  TaintSnapshot,
  Timing,
  ToolCall,
} from '../src/types.ts'
import {
  ASK_ALLOW,
  ASK_REFUSE,
  argSummary,
  askQuestion,
  askRefusedText,
  auditReport,
  bandText,
  clearDeclinedText,
  clearRefusedText,
  clearedText,
  denyText,
  explainReport,
  failureDenyText,
  labelList,
  nothingToClearText,
  promptContextLine,
  refusalCountLine,
  refusalLogLine,
  sourceTools,
  statusReport,
  taintContextLine,
} from '../src/ui.ts'
import {
  EMPTY_SUMMARY,
  USAGE,
  mergeStored,
  messageOf,
  readOptions,
  rebuildDetail,
  splitCommand,
  startedBefore,
  unionTaint,
  type TaintGuardOptions,
} from './support.ts'

type Dollar = EngineInterface

type Ctx = {
  options: TaintGuardOptions
  loaded: LoadedPolicy | null
  enabled: boolean
  preset: PresetName
  headless: boolean
  sessionId: string
  configDir: string | null
  audit: AuditLog | null
  auditKey: string | null
  isFlushing: boolean
  clearedThrough: string | undefined
  carry: TaintSnapshot | null
  lastBandLogged: string | null
  backgroundStarts: Map<string, number>
  refusals: Map<string, number>
  knownTools: Set<string>
}

const PLUGIN = 'taint-guard'
const HEADER = 'TaintGuard'
const HISTORY_LIMIT = 4096
const AGENT_TRANSCRIPTS_MAX = 20
const AUDIT_KEY = 'audit-key'
const DISABLED_KEY = 'disabled-audited'
const FLUSH_MS = 1000

const taintAtom = atom({ plugin: 'taint-guard', key: 'taint' } as const, EMPTY_TAINT)
const statusAtom = atom({ plugin: 'taint-guard', key: 'status' } as const, null)
const toolsAtom = atom({ plugin: 'taint-guard', key: 'tools' } as const, [])
const backgroundAtom = atom({ plugin: 'taint-guard', key: 'background' } as const, [])

const iso = (at: number): string => new Date(at).toISOString()

function append(ctx: Ctx, at: number, entry: Omit<AuditEntry, 'ts'>): void {
  ctx.audit?.append({ ts: iso(at), ...entry })
}

async function flushAudit(ctx: Ctx): Promise<void> {
  try {
    await ctx.audit?.flush()
  } catch {}
}

async function callEntry(
  ctx: Ctx,
  event: AuditEvent,
  call: ToolCall,
  at: number,
  fields: Pick<AuditEntry, 'rule' | 'labels' | 'detail'>,
): Promise<void> {
  const audit = ctx.audit
  if (audit === null) return
  const entry: AuditEntry = { ts: iso(at), event, tool: call.tool, ...fields }
  if (call.toolUseId !== undefined) entry.toolUseId = call.toolUseId
  if (call.agentId !== undefined) entry.agentId = call.agentId
  if (ctx.auditKey !== null) {
    try {
      entry.argsHmac = await hmacHex(ctx.auditKey, canonicalJson(call.args))
    } catch {}
  }
  if (ctx.options.auditArguments) entry.args = argsSnippet(call.args)
  audit.append(entry)
}

function heldLabels(ctx: Ctx, policy: CompiledPolicy, taint: TaintSnapshot): string[] {
  return ctx.loaded?.lockdown ? allLabels(policy) : [...taint.labels]
}

function toCall(e: Readonly<Record<string, unknown>> & { tool: string; tool_use_id: string; agentId?: string }): ToolCall {
  const call: ToolCall = { tool: e.tool, args: callArguments(e), toolUseId: e.tool_use_id }
  if (e.agentId !== undefined) call.agentId = e.agentId
  return call
}

function sourcesFor(policy: CompiledPolicy, call: ToolCall, timing: Timing, trustedOnly: boolean): CompiledSource[] {
  return trustedOnly
    ? policy.sources.filter((source) => source.trusted && source.on === timing && source.test(call))
    : matchSources(policy, call, timing)
}

function noteRefusal($: Dollar, ctx: Ctx, tool: string, rule: string): void {
  const count = (ctx.refusals.get(tool) ?? 0) + 1
  ctx.refusals.set(tool, count)
  if (count === 1) $.ui.log(refusalLogLine(tool, rule))
}

async function safeNow($: Dollar): Promise<number> {
  try {
    return await $.clock.now()
  } catch {
    return Date.now()
  }
}

async function readLayer($: Dollar, layer: LayerText['layer'], path: string): Promise<LayerText> {
  try {
    if (!(await $.fs.exists(path))) return { layer, path, text: null }
    return { layer, path, text: await $.fs.read(path) }
  } catch (error) {
    return { layer, path, text: null, readError: messageOf(error) }
  }
}

async function loadAll($: Dollar, ctx: Ctx, cwd: string): Promise<LoadedPolicy> {
  let settings: unknown = {}
  let managedReadError: string | undefined
  try {
    settings = await $.settings.read({ source: 'policy' })
  } catch (error) {
    managedReadError = messageOf(error)
  }
  const managed = managedOptionsFrom(settings, PLUGIN)
  ctx.enabled = managedReadError !== undefined || managed.enabled === true || ctx.options.enabled
  const effective = effectivePreset(ctx.options.preset, managed)
  ctx.preset = effective.preset
  const home = (await $.env.get('HOME')) ?? (await $.env.get('USERPROFILE'))
  const managedPath = managed.managedPolicyPath === undefined ? null : expandHome(managed.managedPolicyPath, home)
  const [managedLayer, userLayer, projectLayer] = await Promise.all([
    managedPath === null ? Promise.resolve(null) : readLayer($, 'managed', managedPath),
    readLayer($, 'user', expandHome(ctx.options.userPolicyPath, home)),
    readLayer($, 'project', `${cwd.replace(/[\\/]+$/, '')}/.claude/taint-guard.json`),
  ])
  const warning = ignoredManagedPathWarning(ctx.options.managedPolicyPath, managed)
  const result = loadPolicy(
    {
      preset: effective.preset,
      presetFromManaged: effective.fromManaged,
      managed: managedLayer,
      user: userLayer,
      project: projectLayer,
      ...(managedReadError === undefined ? {} : { managedReadError }),
      warnings: warning === null ? [] : [warning],
    },
    PRESETS,
  )
  ctx.loaded = result
  const at = await safeNow($)
  const enabled = ctx.enabled
  await update($, statusAtom, () => ({
    enabled,
    preset: effective.preset,
    lockdown: result.lockdown,
    layers: result.layers,
    warnings: result.warnings,
    loadedAt: at,
  }))
  if (enabled) for (const text of result.warnings) $.ui.log(`TaintGuard: ${text}`)
  return result
}

function auditLockdown(ctx: Ctx, at: number): void {
  const lockdown = ctx.loaded?.lockdown
  if (ctx.enabled && lockdown) append(ctx, at, { event: 'lockdown', detail: lockdown })
}

async function isOn($: Dollar, ctx: Ctx): Promise<boolean> {
  await ensureLoaded($, ctx)
  return ctx.enabled
}

async function ensureLoaded($: Dollar, ctx: Ctx): Promise<LoadedPolicy> {
  if (ctx.loaded !== null) return ctx.loaded
  if (ctx.sessionId === '') ctx.sessionId = await $.session.id()
  return loadAll($, ctx, await $.session.cwd())
}

async function loadAuditKey($: Dollar): Promise<string> {
  const stored = await $.store.get(AUDIT_KEY)
  if (typeof stored === 'string' && /^[0-9a-f]{64}$/i.test(stored)) return stored
  const fresh = await generateKeyHex()
  await $.store.set(AUDIT_KEY, fresh)
  return fresh
}

async function openAudit($: Dollar, ctx: Ctx): Promise<void> {
  if (!ctx.options.auditLog) return
  ctx.configDir = configDirFrom({
    CLAUDE_CONFIG_DIR: await $.env.get('CLAUDE_CONFIG_DIR'),
    HOME: await $.env.get('HOME'),
    USERPROFILE: await $.env.get('USERPROFILE'),
  })
  if (ctx.configDir === null) return
  try {
    ctx.auditKey = await loadAuditKey($)
  } catch {
    ctx.auditKey = null
  }
  const path = auditPath(ctx.configDir, ctx.sessionId)
  if (ctx.audit === null) {
    ctx.audit = createAuditLog(
      {
        read: async (file) => ((await $.fs.exists(file)) ? await $.fs.read(file) : null),
        write: (file, text) => $.fs.write(file, text),
      },
      { path },
    )
  } else {
    await ctx.audit.setPath(path).catch(() => undefined)
  }
  if (!ctx.isFlushing) {
    ctx.isFlushing = true
    $.clock.every(FLUSH_MS, () => void flushAudit(ctx))
  }
}

async function switchSession(ctx: Ctx, id: string): Promise<void> {
  ctx.sessionId = id
  if (ctx.audit !== null && ctx.configDir !== null) await ctx.audit.setPath(auditPath(ctx.configDir, id)).catch(() => undefined)
}

async function saveStore($: Dollar, ctx: Ctx, taint: TaintSnapshot, at: number): Promise<void> {
  try {
    await $.store.set(storeKey(ctx.sessionId), toStored(taint, at, ctx.clearedThrough))
  } catch (error) {
    $.ui.log(`TaintGuard could not save the taint copy: ${messageOf(error)}`, { to: 'debug' })
  }
}

async function pruneStore($: Dollar, ctx: Ctx, at: number): Promise<void> {
  try {
    const own = storeKey(ctx.sessionId)
    const keys = (await $.store.keys()).filter((key) => key !== own && key.startsWith(storeKey('')))
    const entries = await Promise.all(keys.map(async (key) => [key, await $.store.get(key)] as const))
    for (const key of staleStoreKeys(entries, at)) await $.store.delete(key)
  } catch {}
}

async function agentTranscripts($: Dollar, messages: readonly SessionMessage[]): Promise<SessionMessage[][]> {
  const ids: string[] = []
  for (const message of messages) {
    for (const use of message.toolUses) {
      if (use.agentId !== undefined && !ids.includes(use.agentId)) ids.push(use.agentId)
    }
  }
  const out: SessionMessage[][] = []
  for (const agentId of ids.slice(-AGENT_TRANSCRIPTS_MAX)) {
    try {
      const found = await $.session.messages({ agentId })
      if (Array.isArray(found)) out.push(found)
    } catch {}
  }
  return out
}

async function rebuildTaint($: Dollar, policy: CompiledPolicy, copy: StoredTaint | null, at: number): Promise<RebuildResult> {
  let messages: SessionMessage[] = []
  let historyLimit = HISTORY_LIMIT
  try {
    messages = await $.session.messages()
  } catch {
    historyLimit = 0
  }
  return rebuild({
    messages,
    agentMessages: await agentTranscripts($, messages),
    match: (call, timing) => matchSources(policy, call, timing),
    declaredLabels: allLabels(policy),
    onUnknownHistory: policy.onUnknownHistory,
    storeCopy: copy,
    historyLimit,
    at,
  })
}

async function applyRebuild($: Dollar, ctx: Ctx, origin: string, result: RebuildResult, at: number): Promise<void> {
  ctx.knownTools.clear()
  await update($, taintAtom, () => result.snapshot)
  if (result.added.length === 0) return
  append(ctx, at, { event: 'rebuild', labels: result.added, detail: rebuildDetail(origin, result.records, result.truncated) })
  await saveStore($, ctx, result.snapshot, at)
}

async function summaryFor($: Dollar, policy: CompiledPolicy, labels: readonly string[]): Promise<ActiveSummary> {
  const summary = activeSummary(policy, new Set(labels), await read($, toolsAtom))
  return {
    ...summary,
    deniedPatterns: summary.deniedPatterns.map(describePattern),
    askedPatterns: summary.askedPatterns.map(describePattern),
  }
}

async function syncHeadlessBand($: Dollar, ctx: Ctx): Promise<void> {
  const loaded = ctx.loaded
  if (!ctx.headless || !ctx.enabled || !ctx.options.showBand || loaded === null) return
  const taint = await read($, taintAtom)
  const summary = await summaryFor($, loaded.policy, heldLabels(ctx, loaded.policy, taint))
  const text = bandText({ taint, lockdown: loaded.lockdown, summary })
  if (text !== null && text !== ctx.lastBandLogged) $.ui.log(text)
  ctx.lastBandLogged = text
}

async function noteTool($: Dollar, ctx: Ctx, tool: string): Promise<void> {
  if (ctx.knownTools.has(tool)) return
  ctx.knownTools.add(tool)
  await update($, toolsAtom, (list) => (list.includes(tool) ? list : [...list, tool]))
}

async function refuse($: Dollar, ctx: Ctx, tool: string, rule: string, text: string): Promise<{ deny: string }> {
  await update($, taintAtom, countBlocked)
  noteRefusal($, ctx, tool, rule)
  return { deny: text }
}

async function fireSources(
  $: Dollar,
  ctx: Ctx,
  policy: CompiledPolicy,
  call: ToolCall,
  timing: Timing,
  at: number,
  trustedOnly = false,
): Promise<string[]> {
  const grew: string[] = []
  for (const source of sourcesFor(policy, call, timing, trustedOnly)) {
    const firing: Firing = { rule: source.id, tool: call.tool, labels: [...source.taints], at }
    if (call.agentId !== undefined) firing.agentId = call.agentId
    if (call.toolUseId !== undefined) firing.toolUseId = call.toolUseId
    let added: string[] = []
    await update($, taintAtom, (current) => {
      const step = addFiring(current, firing)
      added = step.added
      return step.next
    })
    if (added.length === 0) continue
    grew.push(...added)
    const entry: Omit<AuditEntry, 'ts'> = { event: 'taint', tool: call.tool, rule: source.id, labels: added }
    if (call.toolUseId !== undefined) entry.toolUseId = call.toolUseId
    if (call.agentId !== undefined) entry.agentId = call.agentId
    append(ctx, at, entry)
  }
  return grew
}

async function askUser($: Dollar, call: ToolCall, reason: string, labels: readonly string[]): Promise<boolean> {
  const question = askQuestion({ tool: call.tool, argSummary: argSummary(call.tool, call.args), reason, labels })
  try {
    return (await $.ui.ask(question, { options: [ASK_ALLOW, ASK_REFUSE], header: HEADER })) === ASK_ALLOW
  } catch {
    return false
  }
}

async function grown(
  $: Dollar,
  ctx: Ctx,
  policy: CompiledPolicy,
  call: ToolCall,
  added: readonly string[],
  result: ToolCallResult,
  at: number,
): Promise<ToolCallResult> {
  const taint = await read($, taintAtom)
  await saveStore($, ctx, taint, at)
  await syncHeadlessBand($, ctx)
  if (result.deny !== undefined) return result
  const line = taintContextLine({
    labels: [...new Set(added)].sort(),
    fromTools: [call.tool],
    summary: await summaryFor($, policy, heldLabels(ctx, policy, taint)),
  })
  return { ...result, context: [...(result.context ?? []), line] }
}

async function statusText($: Dollar, ctx: Ctx): Promise<string> {
  const current = await ensureLoaded($, ctx)
  const { policy, lockdown } = current
  const taint = await read($, taintAtom)
  const held = heldLabels(ctx, policy, taint)
  const active = new Set(held)
  return statusReport({
    taint,
    lockdown,
    enabled: ctx.enabled,
    preset: ctx.preset,
    layers: current.layers,
    warnings: current.warnings,
    activeSinks: policy.sinks
      .filter((sink) => isSinkActive(sink, active))
      .map((sink) => ({ id: sink.id, action: sink.action, reason: sink.reason })),
    summary: ctx.enabled ? await summaryFor($, policy, held) : EMPTY_SUMMARY,
    background: await read($, backgroundAtom),
  })
}

async function explainCommand($: Dollar, ctx: Ctx, rest: string): Promise<string> {
  const parsed = parseExplainArgs(rest)
  if ('error' in parsed) return parsed.error
  const { policy, lockdown } = await ensureLoaded($, ctx)
  const taint = await read($, taintAtom)
  const call: ToolCall = { tool: parsed.tool, args: parsed.args }
  return explainReport({
    tool: parsed.tool,
    args: parsed.args,
    decision: evaluateSinks(policy, call, new Set(heldLabels(ctx, policy, taint))),
    wouldTaint: [...matchSources(policy, call, 'attempt'), ...matchSources(policy, call, 'success')].map((source) => ({
      id: source.id,
      on: source.on,
      taints: source.taints,
    })),
    labels: taint.labels,
    lockdown,
  })
}

async function toolsCommand($: Dollar, ctx: Ctx): Promise<string> {
  const { policy } = await ensureLoaded($, ctx)
  const tools = await read($, toolsAtom)
  return toolsReport({ tools, sources: policy.sources, sinks: policy.sinks, classify: classifyTool }).text
}

async function clearCommand($: Dollar, ctx: Ctx, e: CommandRunInput, rest: string): Promise<string> {
  if (e.origin.kind !== 'composer' && e.origin.kind !== 'bridge') {
    return 'TaintGuard: only the user can clear labels, by typing /taintguard clear at the prompt.'
  }
  const { policy } = await ensureLoaded($, ctx)
  if (policy.userDeclassify === 'never') return clearRefusedText(policy.userDeclassifyFrom)
  const { labels } = parseClearArgs(rest)
  const preview = removeLabels(await read($, taintAtom), labels)
  if (preview.removed.length === 0) return nothingToClearText()
  if (policy.userDeclassify === 'confirm') {
    const question = `Clear ${labelList(preview.removed)} from this session, so TaintGuard stops refusing tools for it?`
    let answer: string | undefined
    try {
      answer = await $.ui.ask(question, { options: ['Clear', 'Keep'], header: HEADER })
    } catch {
      answer = undefined
    }
    if (answer !== 'Clear') return clearDeclinedText()
  }
  let removed: string[] = []
  const after = await update($, taintAtom, (current) => {
    const step = removeLabels(current, labels)
    removed = step.removed
    return step.next
  })
  if (removed.length === 0) return nothingToClearText()
  try {
    ctx.clearedThrough = lastToolUseId(await $.session.messages()) ?? ctx.clearedThrough
  } catch {}
  const at = await $.clock.now()
  await saveStore($, ctx, after, at)
  const still = after.labels.length > 0 ? labelList(after.labels) : 'none'
  append(ctx, at, { event: 'declassify', labels: removed, detail: `by /taintguard clear (${e.origin.kind}); still present: ${still}` })
  await syncHeadlessBand($, ctx)
  return clearedText(removed, after.labels)
}

async function reloadCommand($: Dollar, ctx: Ctx): Promise<string> {
  const result = await loadAll($, ctx, await $.session.cwd())
  const layers = result.layers.map((layer) => `${layer.layer} ${layer.status}`).join(', ')
  const detail = result.lockdown === null ? `preset ${ctx.preset}; ${layers}` : `lockdown: ${result.lockdown}`
  const at = await $.clock.now()
  append(ctx, at, { event: 'reload', detail })
  auditLockdown(ctx, at)
  await syncHeadlessBand($, ctx)
  return `TaintGuard reloaded the policy; the taint set is unchanged.\n\n${await statusText($, ctx)}`
}

async function auditCommand(ctx: Ctx): Promise<string> {
  const audit = ctx.audit
  if (audit === null) return 'TaintGuard: the audit log is off (auditLog option).'
  await flushAudit(ctx)
  return auditReport(audit.path(), await audit.tail(20))
}

async function runCommand($: Dollar, ctx: Ctx, e: CommandRunInput): Promise<string> {
  const { sub, rest } = splitCommand(e.args)
  switch (sub) {
    case '':
    case 'status':
      return statusText($, ctx)
    case 'explain':
      return explainCommand($, ctx, rest)
    case 'tools':
      return toolsCommand($, ctx)
    case 'clear':
      return clearCommand($, ctx, e, rest)
    case 'reload':
      return reloadCommand($, ctx)
    case 'audit':
      return auditCommand(ctx)
    default:
      return USAGE
  }
}

async function startSession(
  $: Dollar,
  ctx: Ctx,
  e: { cwd: string; surface: unknown; isInteractive: boolean },
): Promise<void> {
  ctx.headless = !e.isInteractive || e.surface === null
  ctx.sessionId = await $.session.id()
  const { policy } = await loadAll($, ctx, e.cwd)
  await openAudit($, ctx)
  await $.command.register({
    name: 'taintguard',
    description: 'TaintGuard: taint status, explain a call, tools, clear labels, reload the policy, audit log',
    argumentHint: '[explain <tool> [json] | tools | clear [label…] | reload | audit]',
    immediate: true,
  })
  const at = await $.clock.now()
  auditLockdown(ctx, at)
  if (!ctx.enabled) {
    if (ctx.audit !== null && (await $.store.get(DISABLED_KEY)) !== ctx.sessionId) {
      append(ctx, at, { event: 'disabled', detail: 'TaintGuard is off: no tool call is checked' })
      await $.store.set(DISABLED_KEY, ctx.sessionId)
    }
    return
  }
  await pruneStore($, ctx, at)
  const own = parseStored(await $.store.get(storeKey(ctx.sessionId)))
  ctx.clearedThrough = own?.clearedThrough
  const state = await $.state.get({ plugin: 'taint-guard', key: 'taint' })
  if (state.version === 0) await applyRebuild($, ctx, 'restart', await rebuildTaint($, policy, own, at), at)
  await syncHeadlessBand($, ctx)
}

async function guardCall(
  $: Dollar,
  ctx: Ctx,
  e: Readonly<Record<string, unknown>> & { tool: string; tool_use_id: string; agentId?: string },
  next: () => Promise<ToolCallResult>,
): Promise<ToolCallResult> {
  const at = await $.clock.now()
  const { policy, lockdown } = await ensureLoaded($, ctx)
  await noteTool($, ctx, e.tool)
  const call = toCall(e)
  const before = await read($, taintAtom)
  const held = heldLabels(ctx, policy, before)
  const decision = evaluateSinks(policy, call, new Set(held))
  const primary = decision.primary
  if (primary !== undefined) {
    const rule = primary.sink.id
    const words = { tool: call.tool, reason: primary.sink.reason, labels: held, fromTools: sourceTools(before), rule, lockdown }
    if (decision.action === 'deny') {
      await callEntry(ctx, 'deny', call, at, { rule, labels: held })
      return refuse($, ctx, call.tool, rule, denyText(words))
    }
    if (decision.action === 'ask') {
      if (!(await askUser($, call, primary.sink.reason, held))) {
        await callEntry(ctx, 'ask-refused', call, at, { rule, labels: held })
        return refuse($, ctx, call.tool, rule, askRefusedText(words))
      }
      await callEntry(ctx, 'ask-allowed', call, at, { rule, labels: held })
    }
    if (decision.action === 'audit') await callEntry(ctx, 'audit-match', call, at, { rule, labels: held })
  }
  if (e.tool === 'Bash' && e.run_in_background === true && typeof e.command === 'string') ctx.backgroundStarts.set(e.command, at)
  const added = await fireSources($, ctx, policy, call, 'attempt', at)
  const result = await next()
  if (result.deny === undefined && result.isError !== true) {
    added.push(...(await fireSources($, ctx, policy, call, 'success', await $.clock.now())))
  }
  if (added.length === 0) return result
  return grown($, ctx, policy, call, added, result, at)
}

async function guardFailed(
  $: Dollar,
  ctx: Ctx,
  e: Readonly<Record<string, unknown>> & { tool: string; tool_use_id: string; agentId?: string },
  failure: { kind: string; message?: string; called: boolean },
  next: () => Promise<ToolCallResult>,
): Promise<ToolCallResult> {
  const at = await safeNow($)
  const call = toCall(e)
  const loaded = ctx.loaded
  if (failure.called) {
    const result = await next()
    if (loaded !== null && result.deny === undefined && result.isError !== true) {
      await fireSources($, ctx, loaded.policy, call, 'success', at, true).catch(() => [])
    }
    return result
  }
  if (loaded === null) {
    append(ctx, at, { event: 'guard-failure', tool: call.tool, detail: `${failure.kind}: no policy loaded` })
    return { deny: failureDenyText(call.tool, failure.kind) }
  }
  const policy = loaded.policy
  let labels = allLabels(policy)
  try {
    labels = heldLabels(ctx, policy, await read($, taintAtom))
  } catch {}
  const decision = failSafeDecision(policy, call, new Set(labels))
  if (decision.action !== 'allow') {
    const rule = decision.primary?.sink.id ?? 'fail-safe'
    const detail = failure.message === undefined ? failure.kind : `${failure.kind}: ${failure.message}`
    await callEntry(ctx, 'guard-failure', call, at, { rule, labels, detail })
    noteRefusal($, ctx, call.tool, rule)
    return { deny: failureDenyText(call.tool, failure.kind) }
  }
  await fireSources($, ctx, policy, call, 'attempt', at, true).catch(() => [])
  const result = await next()
  if (result.deny === undefined && result.isError !== true) {
    await fireSources($, ctx, policy, call, 'success', at, true).catch(() => [])
  }
  return result
}

async function classicStart(
  $: Dollar,
  ctx: Ctx,
  e: { source: 'startup' | 'resume' | 'clear' | 'compact' | 'fork'; session_id: string },
): Promise<void> {
  const previous = ctx.sessionId
  await switchSession(ctx, e.session_id)
  if (!(await isOn($, ctx))) return
  const { policy } = await ensureLoaded($, ctx)
  const at = await $.clock.now()
  if (e.source === 'clear') {
    const both = unionTaint(await read($, taintAtom), ctx.carry ?? EMPTY_TAINT, at)
    ctx.carry = null
    ctx.clearedThrough = undefined
    if (policy.resetOnClear) {
      await update($, taintAtom, () => EMPTY_TAINT)
      if (both.labels.length > 0) append(ctx, at, { event: 'reset', labels: both.labels, detail: '/clear with resetOnClear' })
    } else {
      await update($, taintAtom, () => both)
      if (both.labels.length > 0) await saveStore($, ctx, both, at)
    }
  } else if (e.source === 'resume' || e.source === 'fork') {
    const own = parseStored(await $.store.get(storeKey(e.session_id)))
    const isFork = e.source === 'fork' && previous !== '' && previous !== e.session_id
    const parent = isFork ? parseStored(await $.store.get(storeKey(previous))) : null
    const copy = mergeStored(own, parent)
    ctx.clearedThrough = copy?.clearedThrough
    await applyRebuild($, ctx, e.source, await rebuildTaint($, policy, copy, at), at)
  }
  await syncHeadlessBand($, ctx)
}

async function noteBackground(
  $: Dollar,
  ctx: Ctx,
  tasks: ReadonlyArray<{ id: string; type: string; status: string; description: string; command?: string }>,
): Promise<void> {
  const taint = await read($, taintAtom)
  if (taint.labels.length === 0) return
  const firstAt = taint.firedBy.reduce<number | undefined>((min, f) => (min === undefined || f.at < min ? f.at : min), undefined)
  const noted = new Set((await read($, backgroundAtom)).map((task) => task.id))
  const at = await $.clock.now()
  for (const task of tasks) {
    if (noted.has(task.id) || !/^(running|pending)$/i.test(task.status)) continue
    if (!startedBefore(ctx.backgroundStarts, task.command, firstAt)) continue
    noted.add(task.id)
    const entry = {
      id: task.id,
      type: task.type,
      description: task.description,
      notedAt: at,
      ...(task.command === undefined ? {} : { command: task.command }),
    }
    await update($, backgroundAtom, (list) => (list.some((one) => one.id === task.id) ? list : [...list, entry]))
    const command = task.command === undefined ? '' : `: ${task.command}`
    append(ctx, at, {
      event: 'background-before-taint',
      labels: [...taint.labels],
      detail: `${task.id} (${task.type}) ${task.description}${command}`,
    })
  }
}

async function promptContext($: Dollar, ctx: Ctx): Promise<string | null> {
  const { policy, lockdown } = await ensureLoaded($, ctx)
  const taint = await read($, taintAtom)
  if (lockdown === null && taint.labels.length === 0) return null
  return promptContextLine({
    labels: taint.labels,
    fromTools: sourceTools(taint),
    summary: await summaryFor($, policy, heldLabels(ctx, policy, taint)),
    lockdown,
  })
}

async function bandFor($: Dollar, ctx: Ctx): Promise<{ text: string; isLockdown: boolean } | null> {
  const status = await read($, statusAtom)
  const loaded = ctx.loaded
  if (status === null || !status.enabled || loaded === null) return null
  const taint = await read($, taintAtom)
  const lockdown = status.lockdown
  if (lockdown === null && taint.labels.length === 0) return null
  const held = lockdown === null ? taint.labels : allLabels(loaded.policy)
  const text = bandText({ taint, lockdown, summary: await summaryFor($, loaded.policy, held) })
  return text === null ? null : { text, isLockdown: lockdown !== null }
}

export const register: Register = (on, rawOptions) => {
  const options = readOptions(rawOptions)
  const ctx: Ctx = {
    options,
    loaded: null,
    enabled: options.enabled,
    preset: 'trifecta',
    headless: false,
    sessionId: '',
    configDir: null,
    audit: null,
    auditKey: null,
    isFlushing: false,
    clearedThrough: undefined,
    carry: null,
    lastBandLogged: null,
    backgroundStarts: new Map(),
    refusals: new Map(),
    knownTools: new Set(),
  }

  on('session.start', async ($, e, next) => {
    await startSession($, ctx, e)
    return next(e)
  }).catch(($, e, next) => next(e))

  on('tool.call', async ($, e, next) => {
    if (!(await isOn($, ctx))) return next(e)
    return guardCall($, ctx, e, () => next(e))
  }).catch(async ($, e, next) => {
    const failure = { kind: next.error.kind, called: next.called, ...(next.error.message === undefined ? {} : { message: next.error.message }) }
    return guardFailed($, ctx, e, failure, () => next(e))
  })

  on('classic.SessionStart', { source: ['clear', 'resume', 'fork'] }, async ($, e, next) => {
    await classicStart($, ctx, e)
    return next(e)
  }).catch(($, e, next) => next(e))

  on('classic.Stop', async ($, e, next) => {
    const tasks = e.background_tasks ?? []
    if (tasks.length > 0 && (await isOn($, ctx))) await noteBackground($, ctx, tasks)
    return next(e)
  }).catch(($, e, next) => next(e))

  on('tool.describe', async ($, e, next) => {
    if (await isOn($, ctx)) await noteTool($, ctx, e.tool)
    return next(e)
  }).catch(($, e, next) => next(e))

  on('session.end', async ($, e, next) => {
    if (e.reason === 'clear') ctx.carry = await read($, taintAtom)
    await flushAudit(ctx)
    return next(e)
  }).catch(($, e, next) => next(e))

  on('session.compact', async ($, e, next) => {
    if (!(await isOn($, ctx))) return next(e)
    const labels = [...(await read($, taintAtom)).labels]
    if (labels.length === 0) return next(e)
    const result = await next({ ...e, instructions: compactInstructions(e.instructions, labels) })
    if (result.skip !== undefined) return result
    const detail = `trigger ${e.trigger}${e.agentId === undefined ? '' : `, agent ${e.agentId}`}`
    append(ctx, await safeNow($), { event: 'compact', labels, detail })
    return { ...result, messages: [...result.messages, { role: 'user', text: formatRecord(labels), toolUses: [] }] }
  }).catch(($, e, next) => next(e))

  on('prompt.submit', async ($, e, next) => {
    if (!(await isOn($, ctx))) return next(e)
    const line = await promptContext($, ctx)
    return line === null ? next(e) : next({ ...e, context: [...(e.context ?? []), line] })
  }).catch(($, e, next) => next(e))

  on('turn.start', async ($, e, next) => {
    ctx.refusals.clear()
    return next(e)
  })

  on('turn.complete', async ($, e, next) => {
    if (e.agentId === undefined) {
      for (const [tool, count] of ctx.refusals) if (count > 1) $.ui.log(refusalCountLine(tool, count))
      ctx.refusals.clear()
    }
    return next(e)
  })

  on('ui.render', { component: 'AbovePrompt' }, async ($, e, next) => {
    if (!ctx.options.showBand || e.props.hasSurvey) return next(e)
    const band = await bandFor($, ctx)
    if (band === null) return next(e)
    const { Box, Text } = $.ui.resolve(e)
    return (
      <Box flexDirection="row">
        <Text color={band.isLockdown ? 'red' : 'yellow'} wrap="truncate-end">
          {band.text}
        </Text>
      </Box>
    )
  })

  on('command.run', { command: 'taintguard' }, async ($, e) => ({ text: await runCommand($, ctx, e) })).catch(
    ($, e, next) => ({ text: `TaintGuard: /taintguard failed (${next.error.message ?? next.error.kind}).` }),
  )
}
