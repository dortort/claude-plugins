import { describe, expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import {
  BAND,
  BY_PERSON,
  BY_SDK,
  EXAMPLE_POLICY,
  GMAIL_READ,
  SESSION_ID,
  SURFACES,
  T0,
  USER_POLICY,
  auditFile,
  call,
  command,
  compact,
  engine,
  labels,
  policyFile,
  said,
  start,
  submit,
  use,
  type Kit,
} from './kit.ts'

const EXAMPLE = { [USER_POLICY]: policyFile(EXAMPLE_POLICY) }
const DAY = 24 * 60 * 60 * 1000
const USAGE = 'Usage: /taintguard [explain <tool> [json args] | tools | clear [label…] | reload | audit]'

async function turn($: Engine, turnId: string, body: () => Promise<void>): Promise<void> {
  await $.turn.start({ text: 'go', turnId })
  await body()
  await $.turn.complete({ answer: 'done', durationMs: 5, isAborted: false, turnId, reason: 'answer' })
}

async function stop($: Engine, tasks: Array<{ id: string; type: string; status: string; description: string; command?: string }>) {
  await $.classic.Stop({ stop_hook_active: false, background_tasks: tasks })
}

async function taintWithMail($: Engine, kit: Kit): Promise<void> {
  await start($, kit)
  await call($, GMAIL_READ, { id: 'm1' })
}

describe('band', () => {
  for (const surface of SURFACES) {
    test(`a clean session leaves the band to the engine (${surface})`, async ($, on) => {
      const kit = engine(on)
      await start($, kit)
      const ui = await $.ui.mount({ ...BAND, surface })
      expect((await ui.find({ type: 'Text' }))?.text).toBe('engine band')
      await ui.unmount()
    })

    test(`a tainted session draws one yellow line (${surface})`, async ($, on) => {
      const kit = engine(on, { files: EXAMPLE })
      await taintWithMail($, kit)
      const ui = await $.ui.mount({ ...BAND, surface })
      const texts = await ui.findAll({ type: 'Text' })
      expect(texts).toHaveLength(1)
      expect(texts[0]?.text).toMatch(
        /^TaintGuard · tainted: private, untrusted \(mcp__gmail__read_message, \d\d:\d\d\) · blocked: Bash · asks: WebFetch · \/taintguard$/,
      )
      expect(texts[0]?.props.color).toBe('yellow')
      expect(texts[0]?.props.wrap).toBe('truncate-end')
      await ui.unmount()
    })

    test(`the band redraws after a declassification (${surface})`, async ($, on) => {
      const kit = engine(on, { answers: ['Clear'] })
      await taintWithMail($, kit)
      const ui = await $.ui.mount({ ...BAND, surface })
      expect((await ui.find({ type: 'Text' }))?.text).toContain('tainted: private, untrusted')
      await command($, 'clear')
      expect((await ui.find({ type: 'Text' }))?.text).toBe('engine band')
      await ui.unmount()
    })

    test(`showBand false leaves the band to the engine while tainted (${surface})`, { options: { showBand: false } }, async ($, on) => {
      const kit = engine(on)
      await taintWithMail($, kit)
      const ui = await $.ui.mount({ ...BAND, surface })
      expect((await ui.find({ type: 'Text' }))?.text).toBe('engine band')
      await ui.unmount()
    })

    test(`a survey keeps the band away (${surface})`, async ($, on) => {
      const kit = engine(on)
      await taintWithMail($, kit)
      const ui = await $.ui.mount({ ...BAND, surface, props: { ...BAND.props, hasSurvey: true } })
      expect((await ui.find({ type: 'Text' }))?.text).toBe('engine band')
      await ui.unmount()
    })
  }

  test('a headless session logs the band text once per change', { options: { preset: 'none' } }, async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit, false)
    expect(kit.logs.filter((line) => line.startsWith('TaintGuard ·'))).toHaveLength(0)
    await call($, GMAIL_READ, { id: 'm1' })
    await call($, GMAIL_READ, { id: 'm2' })
    let bands = kit.logs.filter((line) => line.startsWith('TaintGuard ·'))
    expect(bands).toHaveLength(1)
    expect(bands[0]).toMatch(/^TaintGuard · tainted: private, untrusted \(mcp__gmail__read_message, \d\d:\d\d\) · blocked: Bash · asks: WebFetch/)
    await call($, 'Read', { file_path: '/work/.env' })
    bands = kit.logs.filter((line) => line.startsWith('TaintGuard ·'))
    expect(bands).toHaveLength(2)
    expect(bands[1]).toContain('tainted: private, secret, untrusted')
  })

  test('a headless session in lockdown logs the lockdown line at start', async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: '[]' } })
    await start($, kit, false)
    expect(kit.logs.filter((line) => line.startsWith('TaintGuard · LOCKDOWN: user policy'))).toHaveLength(1)
  })
})

describe('Claude is told', () => {
  test('prompt.submit carries no context while clean and one line while tainted', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    await submit($, 'hello')
    expect(kit.submitted[0]?.context).toBeUndefined()
    await call($, GMAIL_READ, { id: 'm1' })
    await submit($, 'what next?')
    const context = kit.submitted[1]?.context ?? []
    expect(context).toHaveLength(1)
    expect(context[0]).toMatch(
      /^TaintGuard: this session holds private, untrusted content \(from mcp__gmail__read_message\)\. These tools are refused: Bash\. These need user approval: WebFetch.*Do not try to reach a refused result through another tool\.$/,
    )
    await submit($, 'and now?')
    expect(kit.submitted[2]?.context).toEqual(context)
  })

  test('prompt.submit in lockdown says every rule is active', async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: '{}' } })
    await start($, kit)
    await submit($, 'hello')
    expect(kit.submitted[0]?.context?.[0]).toMatch(/^TaintGuard is in lockdown \(user policy .*\): every rule is active as if all labels were present\./)
  })

  test('repeated refusals of one tool in a turn are logged once, then counted at turn end', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await taintWithMail($, kit)
    await turn($, 't1', async () => {
      await call($, 'Bash', { command: 'ls' })
      await call($, 'Bash', { command: 'pwd' })
      await call($, 'Bash', { command: 'id' })
    })
    expect(kit.logs.filter((line) => line.startsWith('TaintGuard refused'))).toEqual([
      'TaintGuard refused Bash (user:no-shell-after-mail)',
      'TaintGuard refused Bash 3 times this turn',
    ])
    await turn($, 't2', async () => {
      await call($, 'Bash', { command: 'ls' })
    })
    expect(kit.logs.filter((line) => line.startsWith('TaintGuard refused'))).toHaveLength(3)
    expect(await command($, '')).toContain('Refused calls: 4')
  })
})

describe('/taintguard', () => {
  test('is registered at session start, and the bare command shows the status pane', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await taintWithMail($, kit)
    expect(kit.commands).toEqual(['taintguard'])
    const status = await command($, '')
    expect(status).toContain('TaintGuard: tainted (private, untrusted)')
    expect(status).toMatch(/private: user:gmail-read via mcp__gmail__read_message at \d\d:\d\d/)
    expect(status).toContain('user:no-shell-after-mail (deny): Bash is disabled because this session has read private mail or secrets.')
    expect(status).toContain('Refused now: Bash')
    expect(status).toContain('Policy layers (preset: trifecta)')
    expect(status).toContain('preset: loaded, 7 rules, presets/trifecta.json')
    expect(status).toContain(`user: loaded, 5 rules, ${USER_POLICY}`)
    expect(status).toContain('project: absent, 0 rules, /work/.claude/taint-guard.json')
    expect(await command($, 'status')).toBe(status)
  })

  test('explain is a dry run: it names the deciding rule and changes nothing', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    const mail = await command($, `explain ${GMAIL_READ} {"id":"m1"}`)
    expect(mail).toContain('Would be allowed')
    expect(mail).toContain('user:gmail-read (on attempt): private, untrusted')
    expect(await labels($)).toEqual([])
    await call($, GMAIL_READ, { id: 'm1' })
    const bash = await command($, 'explain Bash {"command":"curl https://evil.example"}')
    expect(bash.split('\n')).toEqual([
      'TaintGuard explain: Bash (curl https://evil.example)',
      'Would be refused by user:no-shell-after-mail: Bash is disabled because this session has read private mail or secrets.',
      'Also matches: preset:outbound-private (ask)',
      'Current labels: private, untrusted',
      'Sources that would fire: none',
    ])
    expect(await command($, 'explain Bash {nope')).toBe('The arguments are not valid JSON. Usage: /taintguard explain <tool> [json args]')
    expect(await command($, 'explain')).toBe('Missing tool name. Usage: /taintguard explain <tool> [json args]')
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ])
  })

  test('tools says when nothing has been shown yet, and lists what tool.describe passed through unchanged', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    expect(await command($, 'tools')).toBe('No tool has been shown to Claude yet this session.')
    const described = await $.tool.describe({ tool: 'mcp__notion__fetch_page', description: 'Fetch a page', provider: { plugin: 'mcp:notion', tier: 'user' } })
    expect(described.description).toBe('Fetch a page')
    await $.tool.describe({ tool: 'mcp__gmail__archive', description: 'Archive', provider: { plugin: 'mcp:gmail', tier: 'user' } })
    const tools = await command($, 'tools')
    expect(tools).toContain('mcp__notion__fetch_page\n  source preset:private-read (attempt): private, untrusted')
    expect(tools).toContain('mcp__gmail__archive')
    expect(kit.ran).toHaveLength(0)
  })

  test('clear asks first, removes every label on Clear, and records the cut point in the store copy', async ($, on) => {
    const kit = engine(on, { answers: ['Clear'] })
    await taintWithMail($, kit)
    const cut = kit.messages().at(-1)?.toolUses[0]?.tool_use_id
    expect(await command($, 'clear')).toBe('TaintGuard cleared private, untrusted. The session is clean.')
    expect(kit.asked).toEqual([
      {
        question: 'Clear private, untrusted from this session, so TaintGuard stops refusing tools for it?',
        header: 'TaintGuard',
        options: ['Clear', 'Keep'],
      },
    ])
    expect(await labels($)).toEqual([])
    expect(kit.store.get(`taint:${SESSION_ID}`)).toMatchObject({ labels: [], clearedThrough: cut })
    const entry = (await kit.audit()).find((e) => e.event === 'declassify')
    expect(entry).toMatchObject({ labels: ['private', 'untrusted'], detail: 'by /taintguard clear (composer); still present: none' })
  })

  test('clear of one label keeps the others; Keep or a dismissal declines; nothing to clear says so', async ($, on) => {
    const kit = engine(on, { answers: ['Keep', null, 'Clear'] })
    await taintWithMail($, kit)
    expect(await command($, 'clear untrusted')).toBe('Declassification cancelled; labels unchanged.')
    expect(await command($, 'clear untrusted')).toBe('Declassification cancelled; labels unchanged.')
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect(await command($, 'clear untrusted')).toBe('TaintGuard cleared untrusted. Still present: private.')
    expect(await labels($)).toEqual(['private'])
    expect(await command($, 'clear secret')).toBe('TaintGuard: nothing to clear; no matching label is present.')
    expect(kit.asked).toHaveLength(3)
  })

  test('clear is refused when Claude or the SDK runs it, and allowed over Remote Control', async ($, on) => {
    const kit = engine(on, { answers: ['Clear'] })
    await taintWithMail($, kit)
    expect(await command($, 'clear', BY_SDK)).toBe('TaintGuard: only the user can clear labels, by typing /taintguard clear at the prompt.')
    expect(await command($, 'clear', { ...BY_SDK, origin: { kind: 'plugin', name: 'helper' } as never })).toContain('only the user can clear labels')
    expect(kit.asked).toHaveLength(0)
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect(await command($, 'clear', { ...BY_PERSON, origin: { kind: 'bridge' } })).toBe('TaintGuard cleared private, untrusted. The session is clean.')
  })

  test('clear under userDeclassify allow does not ask', async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: policyFile({ ...EXAMPLE_POLICY, userDeclassify: 'allow' }) } })
    await taintWithMail($, kit)
    expect(await command($, 'clear')).toBe('TaintGuard cleared private, untrusted. The session is clean.')
    expect(kit.asked).toHaveLength(0)
  })

  test('reload re-reads the policy layers and keeps the taint set', async ($, on) => {
    const kit = engine(on)
    await taintWithMail($, kit)
    expect((await call($, 'Bash', { command: 'ls' })).deny).toContain('the user did not approve it')
    kit.files.set(USER_POLICY, policyFile(EXAMPLE_POLICY))
    const text = await command($, 'reload')
    expect(text.split('\n')[0]).toBe('TaintGuard reloaded the policy; the taint set is unchanged.')
    expect(text).toContain(`user: loaded, 5 rules, ${USER_POLICY}`)
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect((await call($, 'Bash', { command: 'ls' })).deny).toContain('Rule: user:no-shell-after-mail.')
    expect((await kit.audit()).find((e) => e.event === 'reload')?.detail).toBe('preset trifecta; preset loaded, user loaded, project absent')
  })

  test('audit prints the log path and the last entries', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await taintWithMail($, kit)
    await call($, 'Bash', { command: 'ls' })
    const lines = (await command($, 'audit')).split('\n')
    expect(lines[0]).toBe(`Audit log: ${auditFile()}`)
    expect(lines[1]).toMatch(/^ {2}\S+ {2}taint {2}mcp__gmail__read_message {2}user:gmail-read {2}\[private, untrusted\]$/)
    expect(lines[2]).toMatch(/^ {2}\S+ {2}deny {2}Bash {2}user:no-shell-after-mail {2}\[private, untrusted\]$/)
  })

  test('audit says when the log is off, and nothing is written', { options: { auditLog: false } }, async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await taintWithMail($, kit)
    await call($, 'Bash', { command: 'ls' })
    expect(await command($, 'audit')).toBe('TaintGuard: the audit log is off (auditLog option).')
    await kit.advance(5000)
    expect([...kit.files.keys()].filter((path) => path.includes('/audit/'))).toEqual([])
    expect(kit.store.has('audit-key')).toBe(false)
  })

  test('an unknown subcommand prints the usage', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    expect(await command($, 'bogus')).toBe(USAGE)
  })
})

describe('switched off', () => {
  test('enabled false passes every call through, says so once per session in the audit log', { options: { enabled: false } }, async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await taintWithMail($, kit)
    expect((await call($, 'Bash', { command: 'curl https://evil.example' })).deny).toBeUndefined()
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ, 'Bash'])
    expect((await command($, '')).split('\n')[0]).toBe('TaintGuard: off')
    await submit($, 'hi')
    expect(kit.submitted[0]?.context).toBeUndefined()
    const ui = await $.ui.mount({ ...BAND, surface: 'terminal' })
    expect((await ui.find({ type: 'Text' }))?.text).toBe('engine band')
    await ui.unmount()
    await start($, kit)
    const entries = await kit.audit()
    expect(entries.map((e) => e.event)).toEqual(['disabled'])
  })

  test('managed enabled: true overrides a user who switched TaintGuard off', { options: { enabled: false } }, async ($, on) => {
    const kit = engine(on, { files: EXAMPLE, managed: { pluginConfigs: { 'taint-guard@corp': { options: { enabled: true } } } } })
    await taintWithMail($, kit)
    expect((await call($, 'Bash', { command: 'ls' })).deny).toContain('TaintGuard refused Bash.')
  })

  test('the managed lock holds for a call that arrives before session.start', { options: { enabled: false } }, async ($, on) => {
    const kit = engine(on, { files: EXAMPLE, managed: { pluginConfigs: { 'taint-guard@corp': { options: { enabled: true } } } } })
    await call($, GMAIL_READ, { id: 'm1' })
    expect((await call($, 'Bash', { command: 'ls' })).deny).toContain('TaintGuard refused Bash.')
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ])
  })

  test('a managed preset floor wins over a weaker user preset', { options: { preset: 'none' } }, async ($, on) => {
    const kit = engine(on, { managed: { pluginConfigs: { 'taint-guard': { options: { preset: 'strict' } } } } })
    await start($, kit)
    await call($, 'WebFetch', { url: 'https://example.com/', prompt: 'read' })
    expect((await call($, 'Write', { file_path: '/work/a.txt', content: 'x' })).deny).toContain('Rule: preset:outbound-any.')
  })
})

describe('compaction', () => {
  test('a compaction the chain skips is returned as is, with the taint kept', async ($, on) => {
    const kit = engine(on, { compact: { skip: 'a PreCompact hook blocked it' } })
    await taintWithMail($, kit)
    const result = await compact($, kit)
    expect(result).toEqual({ skip: 'a PreCompact hook blocked it' })
    expect(kit.compacted[0]?.instructions).toContain('TaintGuard taint record v1: labels=private,untrusted')
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect((await kit.audit()).map((e) => e.event)).not.toContain('compact')
  })
})

describe('background tasks', () => {
  test('classic.Stop notes tasks that were running before the first taint, once each', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, 'Bash', { command: 'npm run dev', run_in_background: true })
    await stop($, [{ id: 'b0', type: 'shell', status: 'running', description: 'dev server', command: 'npm run dev' }])
    await kit.advance(5000)
    await call($, 'WebFetch', { url: 'https://example.com/', prompt: 'read' })
    await kit.advance(5000)
    await call($, 'Bash', { command: 'npm run watch', run_in_background: true })
    const tasks = [
      { id: 'b1', type: 'shell', status: 'running', description: 'dev server', command: 'npm run dev' },
      { id: 'b2', type: 'shell', status: 'running', description: 'watcher', command: 'npm run watch' },
      { id: 'b3', type: 'subagent', status: 'running', description: 'research' },
      { id: 'b4', type: 'shell', status: 'completed', description: 'tests', command: 'npm test' },
    ]
    await stop($, tasks)
    await stop($, tasks)
    const status = await command($, '')
    expect(status).toContain('Background tasks started before taint\n  b1 (shell) dev server: npm run dev\n  b3 (subagent) research')
    expect(status).not.toContain('b0 (shell)')
    expect(status).not.toContain('b2 (shell)')
    const notes = (await kit.audit()).filter((e) => e.event === 'background-before-taint')
    expect(notes.map((e) => e.detail)).toEqual(['b1 (shell) dev server: npm run dev', 'b3 (subagent) research'])
    expect(notes[0]?.labels).toEqual(['untrusted'])
  })
})

describe('persistence', () => {
  test('a taint is saved to the store under the session id', async ($, on) => {
    const kit = engine(on)
    await taintWithMail($, kit)
    expect(kit.store.get(`taint:${SESSION_ID}`)).toEqual({
      labels: ['private', 'untrusted'],
      firedBy: [
        {
          rule: 'preset:private-read',
          tool: GMAIL_READ,
          labels: ['private', 'untrusted'],
          at: T0,
          toolUseId: expect.stringMatching(/^toolu_/),
        },
      ],
      savedAt: T0,
    })
  })

  test('a restart rebuilds from the store copy and prunes stale copies', async ($, on) => {
    const kit = engine(on, {
      store: {
        [`taint:${SESSION_ID}`]: { labels: ['secret'], firedBy: [], savedAt: T0 - DAY },
        'taint:old-session': { labels: ['private'], firedBy: [], savedAt: T0 - 15 * DAY },
        'taint:recent-session': { labels: ['private'], firedBy: [], savedAt: T0 - 2 * DAY },
        'taint:broken': { labels: 'nope' },
      },
    })
    await start($, kit)
    expect(await labels($)).toEqual(['secret'])
    expect(kit.store.has('taint:old-session')).toBe(false)
    expect(kit.store.has('taint:broken')).toBe(false)
    expect(kit.store.has('taint:recent-session')).toBe(true)
    expect((await kit.audit()).find((e) => e.event === 'rebuild')).toMatchObject({ labels: ['secret'], detail: 'rebuilt after restart' })
  })

  test('a restart replays only the history after a declassification cut', async ($, on) => {
    const kit = engine(on, {
      messages: [use(GMAIL_READ, { id: 'm1' }, { id: 'toolu_cut' }), said('user', 'thanks'), use('Read', { file_path: '/work/.env' })],
      store: { [`taint:${SESSION_ID}`]: { labels: [], firedBy: [], savedAt: T0, clearedThrough: 'toolu_cut' } },
    })
    await start($, kit)
    expect(await labels($)).toEqual(['secret'])
  })

  test('a restart reads subagent transcripts named by Agent tool uses', async ($, on) => {
    const kit = engine(on, {
      messages: [use('Agent', { prompt: 'triage my inbox' }, { agentId: 'agent-1' }), use('Agent', { prompt: 'x' }, { agentId: 'agent-gone' })],
      agents: { 'agent-1': [use(GMAIL_READ, { id: 'm1' })] },
    })
    await start($, kit)
    expect(await labels($)).toEqual(['private', 'untrusted'])
  })

  test('a fork restores the parent session from its store copy', async ($, on) => {
    const kit = engine(on)
    await taintWithMail($, kit)
    kit.setMessages([])
    await $.classic.SessionStart({ source: 'fork', session_id: 'sess-branch' })
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect(kit.store.get('taint:sess-branch')).toMatchObject({ labels: ['private', 'untrusted'] })
  })

  test('/clear with resetOnClear false keeps the taint under the new session id', async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: policyFile({ ...EXAMPLE_POLICY, resetOnClear: false }) } })
    await taintWithMail($, kit)
    await $.session.end({ reason: 'clear', sessionId: SESSION_ID, resume: { id: SESSION_ID } })
    await $.classic.SessionStart({ source: 'clear', session_id: 'sess-2' })
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect(kit.store.get('taint:sess-2')).toMatchObject({ labels: ['private', 'untrusted'] })
    expect((await kit.audit('sess-2')).map((e) => e.event)).not.toContain('reset')
  })

  test('the guard failing after the tool ran returns the tool result once', async ($, on) => {
    const kit = engine(on)
    kit.tools[GMAIL_READ] = () => {
      kit.faults.clock = true
      return { result: 'the mail', text: 'the mail' }
    }
    await start($, kit)
    const result = await call($, GMAIL_READ, { id: 'm1' })
    kit.faults.clock = false
    expect(result.deny).toBeUndefined()
    expect(result.result).toBe('the mail')
    expect(kit.ran.filter((r) => r.tool === GMAIL_READ)).toHaveLength(1)
    expect(await labels($)).toEqual(['private', 'untrusted'])
  })

  test('the audit file holds one JSON object per line, flushed every second and at session end', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await taintWithMail($, kit)
    await call($, 'Bash', { command: 'ls' })
    expect(kit.files.has(auditFile())).toBe(false)
    await $.session.end({ reason: 'other', sessionId: SESSION_ID, resume: { id: SESSION_ID } })
    const text = kit.files.get(auditFile()) ?? ''
    const rows = text.trimEnd().split('\n').map((line) => JSON.parse(line))
    expect(rows.map((row) => row.event)).toEqual(['taint', 'deny'])
    expect(rows[0]).toEqual({
      ts: new Date(T0).toISOString(),
      event: 'taint',
      tool: GMAIL_READ,
      rule: 'user:gmail-read',
      labels: ['private', 'untrusted'],
      toolUseId: expect.stringMatching(/^toolu_/),
    })
    expect(kit.store.get('audit-key')).toMatch(/^[0-9a-f]{64}$/)
  })
})
