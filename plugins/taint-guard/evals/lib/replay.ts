import { evaluateSinks, loadPolicy, matchSources } from '../../src/policy.ts'
import { PRESETS } from '../../src/presets.ts'
import { EMPTY_TAINT, addFiring } from '../../src/state.ts'
import type { CompiledPolicy, PresetName, TaintSnapshot, Timing, ToolCall } from '../../src/types.ts'

export type Outcome = 'ok' | 'error' | 'permission-denied'
export type Role = 'context' | 'source' | 'collect' | 'exfil' | 'work'
export type AskAnswer = 'allow' | 'refuse'

export type Step = {
  tool: string
  args?: Record<string, unknown>
  agentId?: string
  outcome?: Outcome
  role?: Role
  needed?: boolean
}

export type StepResult = {
  step: Step
  decision: 'allow' | 'deny' | 'ask' | 'audit'
  rule?: string
  passedGuard: boolean
  executed: boolean
  approved: boolean
  labelsBefore: string[]
  added: string[]
}

export function presetPolicy(preset: PresetName): CompiledPolicy {
  const loaded = loadPolicy({ preset, presetFromManaged: false, managed: null, user: null, project: null }, PRESETS)
  if (loaded.lockdown !== null) throw new Error(`preset ${preset} did not load: ${loaded.lockdown}`)
  return loaded.policy
}

/** Replays a trace in hooks/register.tsx guardCall order: sinks on earlier taint, attempt sources, the tool, success sources. */
export function replay(policy: CompiledPolicy, steps: readonly Step[], answer: AskAnswer): StepResult[] {
  let taint: TaintSnapshot = EMPTY_TAINT
  let at = Date.UTC(2026, 10, 2, 9)
  const fire = (call: ToolCall, timing: Timing): string[] => {
    const added: string[] = []
    for (const source of matchSources(policy, call, timing)) {
      const step = addFiring(taint, { rule: source.id, tool: call.tool, labels: [...source.taints], at })
      taint = step.next
      added.push(...step.added)
    }
    return added
  }
  return steps.map((step, index) => {
    at += 1000
    const call: ToolCall = { tool: step.tool, args: step.args ?? {}, toolUseId: `toolu_eval_${index}` }
    if (step.agentId !== undefined) call.agentId = step.agentId
    const labelsBefore = [...taint.labels]
    const decision = evaluateSinks(policy, call, new Set(labelsBefore))
    const result: StepResult = {
      step,
      decision: decision.action,
      passedGuard: false,
      executed: false,
      approved: false,
      labelsBefore,
      added: [],
    }
    if (decision.primary !== undefined) result.rule = decision.primary.sink.id
    if (decision.action === 'deny') return result
    if (decision.action === 'ask') {
      if (answer === 'refuse') return result
      result.approved = true
    }
    result.passedGuard = true
    result.added.push(...fire(call, 'attempt'))
    const outcome = step.outcome ?? 'ok'
    result.executed = outcome !== 'permission-denied'
    if (outcome === 'ok') result.added.push(...fire(call, 'success'))
    return result
  })
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
