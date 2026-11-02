import { describe, expect, test } from 'claude-code/testing'
import { EXAMPLE_POLICY, GMAIL_READ, HOME, USER_POLICY, call, engine, policyFile, start, type Kit } from './kit.ts'
import type { Engine } from 'claude-code/testing'

const REASON = 'TaintGuard does not let a tainted session change its own policy, settings or audit log.'
const RULE = 'Rule: builtin:self-protect.'

async function tainted($: Engine, kit: Kit): Promise<void> {
  await start($, kit)
  await call($, GMAIL_READ, { id: 'm1' })
}

describe('self-protection', () => {
  test('a tainted session cannot write the user policy; a clean one can', async ($, on) => {
    const kit = engine(on)
    await start($, kit)
    expect((await call($, 'Write', { file_path: '~/.claude/taint-guard.json', content: '{}' })).deny).toBeUndefined()
    await call($, GMAIL_READ, { id: 'm1' })
    const result = await call($, 'Write', { file_path: '~/.claude/taint-guard.json', content: '{"version":1}' })
    expect(result.deny).toContain(`TaintGuard refused Write. ${REASON}`)
    expect(result.deny).toContain(RULE)
    expect(kit.ran.map((r) => r.tool)).toEqual(['Write', GMAIL_READ])
    const entry = (await kit.audit()).find((e) => e.event === 'deny')
    expect(entry).toMatchObject({ tool: 'Write', rule: 'builtin:self-protect', labels: ['private', 'untrusted'] })
  })

  test('a relative path that climbs to the user settings is refused', async ($, on) => {
    const kit = engine(on)
    await tainted($, kit)
    expect((await call($, 'Edit', { file_path: '../home/tester/.claude/settings.json', old_string: 'a', new_string: 'b' })).deny).toContain(RULE)
    expect((await call($, 'Write', { file_path: '.claude/./settings.local.json', content: '{}' })).deny).toContain(RULE)
    expect((await call($, 'Write', { file_path: `${HOME}/.claude/taint-guard/audit/x.jsonl`, content: '' })).deny).toContain(RULE)
    expect((await call($, 'Write', { file_path: '/work/notes.md', content: 'x' })).deny).toBeUndefined()
  })

  test('Bash that writes the settings is refused outright, without an ask', async ($, on) => {
    const kit = engine(on, { answers: ['Allow once'] })
    await tainted($, kit)
    const result = await call($, 'Bash', { command: 'echo {} > ~/.claude/settings.json' })
    expect(result.deny).toContain(RULE)
    expect(kit.asked).toHaveLength(0)
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ])
  })

  test('an MCP write tool aimed at a protected path is refused', async ($, on) => {
    const kit = engine(on)
    await tainted($, kit)
    const result = await call($, 'mcp__filesystem__write_file', { path: '/work/.claude/taint-guard.json', content: '{}' })
    expect(result.deny).toContain(RULE)
    expect(kit.ran.map((r) => r.tool)).toEqual([GMAIL_READ])
  })

  test('audit mode does not switch it off', { options: { preset: 'none' } }, async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: policyFile({ ...EXAMPLE_POLICY, mode: 'audit' }) } })
    await tainted($, kit)
    expect((await call($, 'Bash', { command: 'ls' })).deny).toBeUndefined()
    expect((await call($, 'Write', { file_path: USER_POLICY, content: '{}' })).deny).toContain(RULE)
  })

  test('lockdown counts as tainted', async ($, on) => {
    const kit = engine(on, { files: { [USER_POLICY]: '{}' } })
    await start($, kit)
    expect((await call($, 'Write', { file_path: '/work/.claude/settings.json', content: '{}' })).deny).toContain(RULE)
  })
})
