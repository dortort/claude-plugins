import type { CompiledSink, CompiledSource } from './types.ts'

export type ToolClassLike = { family: string | null; verb: string | null }

const EXPLAIN_USAGE = 'Usage: /taintguard explain <tool> [json args]'

const DEPENDS = ' (depends on arguments)'

/** The /taintguard tools report: per tool, the rules that match it and any flags. */
export function toolsReport(input: {
  tools: readonly string[]
  sources: ReadonlyArray<Pick<CompiledSource, 'id' | 'on' | 'taints' | 'testTool'>>
  sinks: ReadonlyArray<Pick<CompiledSink, 'id' | 'action' | 'testTool'>>
  classify: (tool: string) => ToolClassLike
}): { text: string; flagged: string[] } {
  const tools = [...new Set(input.tools)].sort()
  if (tools.length === 0) return { text: 'No tool has been shown to Claude yet this session.', flagged: [] }

  const flagged: string[] = []
  const blocks: string[] = []
  for (const tool of tools) {
    const lines = [tool]
    let sourceHit = false
    let sinkHit = false
    for (const source of input.sources) {
      const match = source.testTool(tool)
      if (match === 'no') continue
      sourceHit = true
      lines.push(`  source ${source.id} (${source.on}): ${[...source.taints].sort().join(', ')}${match === 'maybe' ? DEPENDS : ''}`)
    }
    for (const sink of input.sinks) {
      const match = sink.testTool(tool)
      if (match === 'no') continue
      sinkHit = true
      lines.push(`  sink ${sink.id} (${sink.action})${match === 'maybe' ? DEPENDS : ''}`)
    }
    if (!sourceHit && !sinkHit) lines.push('  no matching rule')

    const { family, verb } = input.classify(tool)
    const flags: string[] = []
    if (family !== null && !sourceHit && !sinkHit) flags.push(`on a ${family} server but matches no rule`)
    if (family !== null && verb === 'other' && sourceHit && sinkHit) {
      flags.push(`unknown verb on a ${family} server: treated as source and sink`)
    }
    for (const flag of flags) lines.push(`  ! ${flag}`)
    if (flags.length > 0) flagged.push(tool)
    blocks.push(lines.join('\n'))
  }

  const shown = `${tools.length} ${tools.length === 1 ? 'tool' : 'tools'} shown this session`
  const header = `TaintGuard tools: ${shown}, ${flagged.length} flagged`
  return { text: [header, ...blocks].join('\n\n'), flagged }
}

/** Parses "<tool> [json object]" after "/taintguard explain". */
export function parseExplainArgs(rest: string): { tool: string; args: Record<string, unknown> } | { error: string } {
  const trimmed = rest.trim()
  const match = /^(\S+)\s*([\s\S]*)$/.exec(trimmed)
  const tool = match?.[1]
  if (tool === undefined) return { error: `Missing tool name. ${EXPLAIN_USAGE}` }
  const json = (match?.[2] ?? '').trim()
  if (json === '') return { tool, args: {} }
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return { error: `The arguments are not valid JSON. ${EXPLAIN_USAGE}` }
  }
  if (parsed === null || typeof parsed !== 'object' || Array.isArray(parsed)) {
    return { error: `The arguments must be a JSON object. ${EXPLAIN_USAGE}` }
  }
  return { tool, args: parsed as Record<string, unknown> }
}

/** Parses the labels after "/taintguard clear"; undefined means every label. */
export function parseClearArgs(rest: string): { labels: string[] | undefined } {
  const words = rest.split(/[\s,]+/).filter((word) => word !== '')
  return { labels: words.length > 0 ? [...new Set(words)] : undefined }
}
