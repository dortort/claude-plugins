import { describe, expect, test } from 'claude-code/testing'
import type { SessionMessage } from 'claude-code'
import { EXAMPLE_POLICY, GMAIL_READ, SESSION_ID, T0, USER_POLICY, call, command, engine, labels, policyFile, said, start, use } from './kit.ts'

const EXAMPLE = { [USER_POLICY]: policyFile(EXAMPLE_POLICY) }
const IGNORE = { [USER_POLICY]: policyFile({ ...EXAMPLE_POLICY, onUnknownHistory: 'ignore' }) }
const ALL = ['private', 'secret', 'untrusted']
const NONE = { options: { preset: 'none' } }
const SECRET_COPY = { [`taint:${SESSION_ID}`]: { labels: ['secret'], firedBy: [], savedAt: T0 } }

describe('rebuild after a resume', () => {
  test('taint a call adds while a resume rebuild is under way is kept', NONE, async ($, on) => {
    const kit = engine(on, { files: EXAMPLE })
    await start($, kit)
    kit.setMessages([use('WebFetch', { url: 'https://example.com/', prompt: 'read' })])
    const release = kit.holdMessages()
    const resumed = $.classic.SessionStart({ source: 'resume', session_id: SESSION_ID })
    await kit.settle()
    await call($, 'Read', { file_path: '/work/.env' })
    release()
    await resumed
    expect(await labels($)).toEqual(['secret', 'untrusted'])
    expect(kit.store.get(`taint:${SESSION_ID}`)).toMatchObject({ labels: ['secret', 'untrusted'] })
  })
})

describe('rebuild from subagents', () => {
  const agentUse = (agentId: string, id?: string): SessionMessage =>
    use('Agent', { prompt: `task for ${agentId}` }, id === undefined ? { agentId } : { agentId, id })

  test('an unreadable subagent transcript counts as unknown history', NONE, async ($, on) => {
    const kit = engine(on, { files: EXAMPLE, messages: [agentUse('agent-gone')] })
    await start($, kit)
    expect(await labels($)).toEqual(ALL)
  })

  test('more subagents than are read counts as unknown history', NONE, async ($, on) => {
    const ids = Array.from({ length: 21 }, (_, i) => `agent-${i}`)
    const kit = engine(on, {
      files: EXAMPLE,
      messages: ids.map((id) => agentUse(id)),
      agents: Object.fromEntries(ids.map((id) => [id, [said('assistant', 'done')]])),
    })
    await start($, kit)
    expect(await labels($)).toEqual(ALL)
  })

  test('twenty readable subagents are not unknown history', NONE, async ($, on) => {
    const ids = Array.from({ length: 20 }, (_, i) => `agent-${i}`)
    const kit = engine(on, {
      files: EXAMPLE,
      messages: ids.map((id) => agentUse(id)),
      agents: Object.fromEntries(ids.map((id) => [id, [said('assistant', 'done')]])),
    })
    await start($, kit)
    expect(await labels($)).toEqual([])
  })

  test('a subagent transcript at the history limit counts as unknown history', NONE, async ($, on) => {
    const long = Array.from({ length: 4096 }, () => said('assistant', 'thinking'))
    const kit = engine(on, { files: EXAMPLE, messages: [agentUse('agent-long')], agents: { 'agent-long': long } })
    await start($, kit)
    expect(await labels($)).toEqual(ALL)
  })

  test('a declassification cut also skips subagents started before it', NONE, async ($, on) => {
    const kit = engine(on, {
      files: EXAMPLE,
      messages: [agentUse('agent-old', 'toolu_cut'), said('user', 'thanks'), agentUse('agent-new')],
      agents: { 'agent-old': [use(GMAIL_READ, { id: 'm1' })], 'agent-new': [use('Read', { file_path: '/work/.env' })] },
      store: { [`taint:${SESSION_ID}`]: { labels: [], firedBy: [], savedAt: T0, clearedThrough: 'toolu_cut' } },
    })
    await start($, kit)
    expect(await labels($)).toEqual(['secret'])
  })
})
