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
