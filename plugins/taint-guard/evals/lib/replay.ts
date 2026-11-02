import { evaluateSinks, isSinkActive, loadPolicy, matchSources } from '../../src/policy.ts'
import { PRESETS } from '../../src/presets.ts'
import { EMPTY_TAINT, addFiring } from '../../src/state.ts'
import type { CompiledPolicy, PresetName, TaintSnapshot, Timing, ToolCall } from '../../src/types.ts'

export type Outcome = 'ok' | 'error' | 'permission-denied'
export type Role = 'context' | 'source' | 'collect' | 'exfil' | 'work'
export type AskAnswer = 'allow' | 'refuse'
export type Gate = 'designed' | 'misfire'
/** Per label a source can add on this step: whether the content really is what the label claims. */
export type Truth = Readonly<Record<string, boolean>>

export type Step = {
  tool: string
  args?: Record<string, unknown>
  agentId?: string
  outcome?: Outcome
  role?: Role
  needed?: boolean
  truth?: Truth
}

export type StepResult = {
  step: Step
  decision: 'allow' | 'deny' | 'ask' | 'audit'
  rule?: string
  passedGuard: boolean
  executed: boolean
  approved: boolean
  labelsBefore: string[]
  /** Held labels that at least one source firing on genuine content added. */
  genuineBefore: string[]
  added: string[]
  /** On ask or deny: designed when a sink with the decision's action is active on genuine labels alone. */
  gate?: Gate
}

export function presetPolicy(preset: PresetName): CompiledPolicy {
  const loaded = loadPolicy({ preset, presetFromManaged: false, managed: null, user: null, project: null }, PRESETS)
  if (loaded.lockdown !== null) throw new Error(`preset ${preset} did not load: ${loaded.lockdown}`)
  return loaded.policy
}

/** Replays a trace in hooks/register.tsx guardCall order: sinks on earlier taint, attempt sources, the tool, success sources. */
export function replay(policy: CompiledPolicy, steps: readonly Step[], answer: AskAnswer): StepResult[] {
  let taint: TaintSnapshot = EMPTY_TAINT
  const genuine = new Set<string>()
  let at = Date.UTC(2026, 10, 2, 9)
  const fire = (call: ToolCall, timing: Timing, truth: Truth | undefined): string[] => {
    const added: string[] = []
    for (const source of matchSources(policy, call, timing)) {
      const step = addFiring(taint, { rule: source.id, tool: call.tool, labels: [...source.taints], at })
      taint = step.next
      added.push(...step.added)
      for (const label of source.taints) if (truth?.[label] === true) genuine.add(label)
    }
    return added
  }
  return steps.map((step, index) => {
    at += 1000
    const call: ToolCall = { tool: step.tool, args: step.args ?? {}, toolUseId: `toolu_eval_${index}` }
    if (step.agentId !== undefined) call.agentId = step.agentId
    const labelsBefore = [...taint.labels]
    const genuineBefore = [...genuine].sort()
    const decision = evaluateSinks(policy, call, new Set(labelsBefore))
    const result: StepResult = {
      step,
      decision: decision.action,
      passedGuard: false,
      executed: false,
      approved: false,
      labelsBefore,
      genuineBefore,
      added: [],
    }
    if (decision.primary !== undefined) result.rule = decision.primary.sink.id
    if (decision.action === 'ask' || decision.action === 'deny') {
      const held = new Set(genuineBefore)
      const designed = decision.matches.some((match) => match.action === decision.action && isSinkActive(match.sink, held))
      result.gate = designed ? 'designed' : 'misfire'
    }
    if (decision.action === 'deny') return result
    if (decision.action === 'ask') {
      if (answer === 'refuse') return result
      result.approved = true
    }
    result.passedGuard = true
    result.added.push(...fire(call, 'attempt', step.truth))
    const outcome = step.outcome ?? 'ok'
    result.executed = outcome !== 'permission-denied'
    if (outcome === 'ok') result.added.push(...fire(call, 'success', step.truth))
    return result
  })
}

/** Labels some source could add on this step that the step's truth does not settle. */
export function untold(policy: CompiledPolicy, step: Step): string[] {
  const call: ToolCall = { tool: step.tool, args: step.args ?? {} }
  const labels = [...matchSources(policy, call, 'attempt'), ...matchSources(policy, call, 'success')].flatMap((source) => source.taints)
  return [...new Set(labels)].filter((label) => step.truth?.[label] === undefined).sort()
}

export function percent(part: number, whole: number): string {
  return whole === 0 ? '0.0%' : `${((100 * part) / whole).toFixed(1)}%`
}

export function table(header: readonly string[], rows: ReadonlyArray<readonly (string | number)[]>): string {
  const cells = [header, ...rows.map((row) => row.map(String))]
  const widths = header.map((_, i) => Math.max(...cells.map((row) => (row[i] ?? '').length)))
  const line = (row: readonly string[]): string => `| ${row.map((cell, i) => cell.padEnd(widths[i] ?? 0)).join(' | ')} |`
  return [line(cells[0] ?? []), `| ${widths.map((w) => '-'.repeat(w)).join(' | ')} |`, ...cells.slice(1).map(line)].join('\n')
}
