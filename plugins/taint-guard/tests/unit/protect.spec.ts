import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { SELF_PROTECT_REASON, SELF_PROTECT_RULE, hasWriteVerb, normalizePath, protectedPaths, selfProtect } from '../../src/protect.ts'
import type { ToolCall } from '../../src/types.ts'

const HOME = '/home/tester'
const CWD = '/work/repo'
const ENV = { cwd: CWD, home: HOME }
const PATHS = protectedPaths({
  userPolicyPath: '~/.claude/taint-guard.json',
  managedPolicyPath: '/etc/claude-code/taint-guard.json',
  cwd: CWD,
  configDir: `${HOME}/.claude`,
  home: HOME,
})

const check = (tool: string, args: Record<string, unknown>): ReturnType<typeof selfProtect> =>
  selfProtect({ tool, args } satisfies ToolCall, PATHS, ENV)

describe('normalizePath', () => {
  it('expands ~, resolves against cwd, collapses . and .., and lower-cases', () => {
    assert.equal(normalizePath('~/.claude/Settings.json', ENV), '/home/tester/.claude/settings.json')
    assert.equal(normalizePath('../../home/tester/./.claude/x', ENV), '/home/tester/.claude/x')
    assert.equal(normalizePath('.claude\\settings.json', ENV), '/work/repo/.claude/settings.json')
    assert.equal(normalizePath('C:\\Users\\Me\\.claude\\..\\.claude\\settings.json', ENV), 'c:/users/me/.claude/settings.json')
    assert.equal(normalizePath('/a/b/../../../c', ENV), '/c')
  })
})

describe('protectedPaths', () => {
  it('lists the policy files, both settings pairs, and the audit and plugin directories', () => {
    assert.deepEqual(PATHS, [
      { path: '/home/tester/.claude/taint-guard.json', isDir: false },
      { path: '/work/repo/.claude/taint-guard.json', isDir: false },
      { path: '/work/repo/.claude/settings.json', isDir: false },
      { path: '/work/repo/.claude/settings.local.json', isDir: false },
      { path: '/etc/claude-code/taint-guard.json', isDir: false },
      { path: '/home/tester/.claude/settings.json', isDir: false },
      { path: '/home/tester/.claude/settings.local.json', isDir: false },
      { path: '/home/tester/.claude/taint-guard', isDir: true },
      { path: '/home/tester/.claude/plugins', isDir: true },
    ])
  })

  it('follows CLAUDE_CONFIG_DIR and a custom user policy path, and skips what is not known', () => {
    const paths = protectedPaths({ userPolicyPath: '/srv/tg.json', managedPolicyPath: null, cwd: CWD, configDir: null })
    assert.deepEqual(
      paths.map((p) => p.path),
      ['/srv/tg.json', '/work/repo/.claude/taint-guard.json', '/work/repo/.claude/settings.json', '/work/repo/.claude/settings.local.json'],
    )
  })
})

describe('selfProtect', () => {
  it('refuses file tools that name a protected file, by any spelling', () => {
    const expected = { rule: SELF_PROTECT_RULE, reason: SELF_PROTECT_REASON }
    assert.deepEqual(check('Write', { file_path: '~/.claude/taint-guard.json', content: '{}' }), expected)
    assert.deepEqual(check('Edit', { file_path: '/HOME/tester/.claude/SETTINGS.json', old_string: 'a', new_string: 'b' }), expected)
    assert.deepEqual(check('MultiEdit', { file_path: '../../home/tester/.claude/settings.local.json', edits: [] }), expected)
    assert.deepEqual(check('Write', { file_path: '.claude/./taint-guard.json', content: '{}' }), expected)
    assert.deepEqual(check('Write', { file_path: 'src/../.claude\\settings.json', content: '{}' }), expected)
    assert.deepEqual(check('Write', { file_path: '/etc/claude-code/taint-guard.json', content: '{}' }), expected)
    assert.deepEqual(check('NotebookEdit', { notebook_path: '/home/tester/.claude/plugins/x/hooks.ipynb', new_source: '' }), expected)
    assert.deepEqual(check('Write', { file_path: '/home/tester/.claude/taint-guard/audit/s.jsonl', content: '' }), expected)
  })

  it('lets file tools write anywhere else', () => {
    assert.equal(check('Write', { file_path: '/work/repo/src/a.ts', content: '' }), null)
    assert.equal(check('Write', { file_path: '/home/tester/.claude/taint-guard.json.bak', content: '' }), null)
    assert.equal(check('Write', { file_path: '/home/tester/.claude/plugins-notes.md', content: '' }), null)
    assert.equal(check('Read', { file_path: '/home/tester/.claude/settings.json' }), null)
    assert.equal(check('Write', { content: 'no path' }), null)
  })

  it('refuses Bash commands that mention the policy or settings', () => {
    assert.notEqual(check('Bash', { command: 'echo {} > ~/.claude/settings.json' }), null)
    assert.notEqual(check('Bash', { command: 'cp x .claude\\settings.local.json' }), null)
    assert.notEqual(check('Bash', { command: 'rm -rf ~/.claude/TAINT-GUARD' }), null)
    assert.notEqual(check('Bash', { command: 'sed -i s/a/b/ settings.local.json' }), null)
    assert.equal(check('Bash', { command: 'ls -la' }), null)
    assert.equal(check('Bash', { description: 'no command' }), null)
  })

  it('refuses MCP write tools whose string arguments name a protected path', () => {
    assert.notEqual(check('mcp__filesystem__write_file', { path: '~/.claude/taint-guard.json', content: '{}' }), null)
    assert.notEqual(check('mcp__fs__moveFile', { source: '/tmp/x', destination: '/home/tester/.claude/settings.json' }), null)
    assert.notEqual(check('mcp__fs__edit_file', { edits: [{ path: '.claude/settings.json' }] }), null)
    assert.equal(check('mcp__filesystem__read_file', { path: '~/.claude/taint-guard.json' }), null)
    assert.equal(check('mcp__filesystem__write_file', { path: '/tmp/notes.txt', content: '~/.claude/settings' }), null)
  })

  it('reads write verbs from the tool name only', () => {
    assert.equal(hasWriteVerb('mcp__fs__write_file'), true)
    assert.equal(hasWriteVerb('mcp__fs__writeFile'), true)
    assert.equal(hasWriteVerb('mcp__fs__create_directory'), true)
    assert.equal(hasWriteVerb('mcp__writer__read_file'), false)
    assert.equal(hasWriteVerb('mcp__fs__get_settings'), false)
  })
})

describe('selfProtect at its limits', () => {
  it('checks destination keys even when other arguments fill the scan', () => {
    const edits = Array.from({ length: 150 }, (_, i) => ({ oldText: `a${i}`, newText: `b${i}` }))
    assert.ok(check('mcp__filesystem__edit_file', { edits, path: '~/.claude/settings.json' }))
  })

  it('fails closed when the arguments are too many or too deep to inspect', () => {
    const many = Array.from({ length: 250 }, (_, i) => `line ${i}`)
    assert.ok(check('mcp__filesystem__write_file', { content: many, where: '/work/repo/out.txt' }))
    let deep: unknown = '/work/repo/out.txt'
    for (let i = 0; i < 10; i += 1) deep = { next: deep }
    assert.ok(check('mcp__filesystem__write_file', { spec: deep }))
    assert.equal(check('mcp__filesystem__write_file', { path: '/work/repo/out.txt', content: 'x' }), null)
  })

  it('refuses moving or deleting a directory that holds protected paths', () => {
    assert.ok(check('mcp__filesystem__move_file', { source: '~/.claude', destination: '/tmp/disabled' }))
    assert.ok(check('mcp__filesystem__delete_directory', { path: '/home/tester' }))
    assert.ok(check('mcp__filesystem__move_file', { source: '/', destination: '/tmp/x' }))
    assert.equal(check('mcp__filesystem__move_file', { source: '/work/repo/a.txt', destination: '/work/repo/b.txt' }), null)
  })

  it('a write to an ancestor directory is not a move: creating a file beside it is allowed', () => {
    assert.equal(check('mcp__filesystem__write_file', { path: '/home/tester/notes.txt', content: 'x' }), null)
  })

  it('refuses Bash commands that touch a .claude directory, not .claude-plugin', () => {
    assert.ok(check('Bash', { command: 'mv ~/.claude /tmp/x' }))
    assert.ok(check('Bash', { command: 'rm -rf "$HOME/.claude"' }))
    assert.equal(check('Bash', { command: 'cat plugins/x/.claude-plugin/plugin.json' }), null)
  })
})
