import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  activeSummary,
  allLabels,
  compileMatcher,
  evaluateSinks,
  failSafeDecision,
  hasNestedQuantifier,
  hasQuantifiedAlternation,
  isSinkActive,
  loadPolicy,
  matchSources,
  resolvePointer,
  validatePolicy,
} from '../../src/policy.ts'
import type { CompiledSink, LayerText, LoadInput, Matcher, PolicyFile, PresetName, ToolCall } from '../../src/types.ts'

const EXAMPLE: PolicyFile = {
  $schema: 'https://raw.githubusercontent.com/dortort/claude-plugins/main/plugins/taint-guard/schema/taint-guard.schema.json',
  version: 1,
  mode: 'enforce',
  subagents: 'shared',
  resetOnClear: true,
  userDeclassify: 'confirm',
  onUnknownHistory: 'assume-tainted',
  labels: {
    private: { description: 'Data the user owns: mail, documents, chats' },
    untrusted: { description: 'Text written by third parties' },
    secret: { description: 'Credentials and keys' },
  },
  sources: [
    {
      id: 'gmail-read',
      match: {
        tool: {
          regex: '^mcp__(claude_ai_)?(gmail|google[_-]?mail)[^_]*__(.*_)?(get|read|search|list|fetch|download|history)',
          flags: 'i',
        },
      },
      on: 'attempt',
      taints: ['private', 'untrusted'],
    },
    {
      id: 'web-content',
      match: { tool: { anyOf: ['WebFetch', 'WebSearch'] } },
      on: 'success',
      taints: ['untrusted'],
    },
    {
      id: 'secret-files',
      match: {
        tool: { exact: 'Read' },
        arguments: [{ pointer: '/file_path', matches: '(^|/)([.]env[^/]*|id_(rsa|ed25519|ecdsa)|credentials)$' }],
      },
      on: 'attempt',
      taints: ['secret'],
    },
  ],
  sinks: [
    {
      id: 'no-shell-after-mail',
      when: { anyOf: ['private', 'secret'] },
      block: [{ tool: { exact: 'Bash' } }],
      action: 'deny',
      reason: 'Bash is disabled because this session has read private mail or secrets.',
    },
    {
      id: 'outbound-after-untrusted-private',
      when: { allOf: ['private', 'untrusted'] },
      block: [
        { tool: { exact: 'WebFetch' } },
        {
          tool: {
            regex: '^mcp__.+__(.*_)?(send|post|reply|forward|create|update|upload|share|schedule|comment|invite)',
            flags: 'i',
          },
        },
      ],
      except: [{ tool: { regex: '^mcp__(claude_ai_)?(gmail|google[_-]?mail)[^_]*__(.*_)?create_draft$', flags: 'i' } }],
      action: 'ask',
      reason: 'This would send data out of a session that holds private, third-party content.',
    },
  ],
}

const STRICT: PolicyFile = {
  version: 1,
  labels: { private: {}, untrusted: {}, secret: {}, lockdown: { description: 'strict-only label' } },
  sources: [{ id: 'web', match: { tool: { anyOf: ['WebFetch'] } }, on: 'success', taints: ['untrusted'] }],
  sinks: [
    {
      id: 'outbound',
      when: { anyOf: ['private', 'untrusted', 'secret'] },
      block: [{ tool: { exact: 'Bash' } }, { tool: { exact: 'WebFetch' } }, { tool: { regex: '^mcp__.+__send', flags: 'i' } }],
    },
  ],
}

const TRIFECTA: PolicyFile = {
  version: 1,
  labels: { private: {}, untrusted: {}, secret: {} },
  sources: [{ id: 'web', match: { tool: { exact: 'WebFetch' } }, on: 'success', taints: ['untrusted'] }],
  sinks: [{ id: 'outbound', when: { allOf: ['private', 'untrusted'] }, block: [{ tool: { exact: 'Bash' } }], action: 'ask' }],
}

const NO_PRESETS: Record<PresetName, PolicyFile | null> = { strict: null, trifecta: null, none: null }
const PRESETS: Record<PresetName, PolicyFile | null> = { strict: STRICT, trifecta: TRIFECTA, none: null }

function base(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { version: 1, labels: { private: {}, untrusted: {}, secret: {} }, ...extra }
}

function errorsOf(value: unknown, layer?: 'project' | 'user'): string[] {
  const result = validatePolicy(value, layer === undefined ? undefined : { layer })
  return result.ok ? [] : result.errors
}

function call(tool: string, args: Record<string, unknown> = {}): ToolCall {
  return { tool, args }
}

function file(layer: LayerText['layer'], policy: unknown, path = `/${layer}.json`): LayerText {
  return { layer, path, text: typeof policy === 'string' ? policy : JSON.stringify(policy) }
}

function load(input: Partial<LoadInput>, presets: Record<PresetName, PolicyFile | null> = NO_PRESETS) {
  return loadPolicy({ preset: 'none', presetFromManaged: false, managed: null, user: null, project: null, ...input }, presets)
}

function sinkRule(id: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { id, when: { anyOf: ['private'] }, block: [{ tool: { exact: 'Bash' } }], ...extra }
}

function sourceRule(id: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return { id, match: { tool: { exact: 'Read' } }, taints: ['private'], ...extra }
}

const set = (...labels: string[]): ReadonlySet<string> => new Set(labels)

describe('validatePolicy', () => {
  it('accepts the spec example policy', () => {
    assert.deepEqual(errorsOf(EXAMPLE), [])
    assert.deepEqual(errorsOf(EXAMPLE, 'project'), [])
  })

  it('returns the policy unchanged on success', () => {
    const result = validatePolicy(EXAMPLE)
    assert.equal(result.ok, true)
    assert.equal(result.ok && result.policy, EXAMPLE)
  })

  const valid: Array<[string, unknown]> = [
    ['minimal policy', base()],
    ['every global', base({ $schema: 'x', description: 'd', mode: 'audit', subagents: 'shared', resetOnClear: false, userDeclassify: 'never', onUnknownHistory: 'ignore' })],
    ['label with description', { version: 1, labels: { 'a-1': { description: 'x' } } }],
    ['32-character label', { version: 1, labels: { [`${'a'.repeat(32)}`]: {} } }],
    ['empty sources and sinks', base({ sources: [], sinks: [] })],
    ['source on success', base({ sources: [sourceRule('a', { on: 'success', enabled: false, description: 'd' })] })],
    ['rule id with dots and underscores', base({ sources: [sourceRule('a.b_c-d')] })],
    ['64-character rule id', base({ sources: [sourceRule('a'.repeat(64))] })],
    ['sink with empty when', base({ sinks: [sinkRule('s', { when: {} })] })],
    ['sink with both conditions', base({ sinks: [sinkRule('s', { when: { anyOf: ['private'], allOf: ['secret'] } })] })],
    ['sink with empty condition arrays', base({ sinks: [sinkRule('s', { when: { anyOf: [], allOf: [] } })] })],
    ['sink with every field', base({ sinks: [sinkRule('s', { except: [], action: 'audit', reason: 'r'.repeat(1000), description: 'd', enabled: true })] })],
    ['source reference', base({ sources: [{ id: 'preset:web-content', enabled: false }] })],
    ['sink reference', base({ sinks: [{ id: 'managed:x', enabled: false }] })],
    ['references to every layer', base({ sinks: ['preset', 'managed', 'user', 'project'].map((l) => ({ id: `${l}:x`, enabled: false })) })],
    ['reference with the same id as a rule', base({ sources: [sourceRule('x'), { id: 'user:x', enabled: false }] })],
    ['prefix selector with flags', base({ sinks: [sinkRule('s', { block: [{ tool: { prefix: 'mcp__', flags: 'i' } }] })] })],
    ['anyOf selector', base({ sinks: [sinkRule('s', { block: [{ tool: { anyOf: ['A', 'B'] } }] })] })],
    ['empty regex', base({ sinks: [sinkRule('s', { block: [{ tool: { regex: '' } }] })] })],
    [
      'every predicate kind',
      base({
        sinks: [
          sinkRule('s', {
            block: [
              {
                tool: { exact: 'Bash' },
                arguments: [
                  { pointer: '', exists: true },
                  { pointer: '/a', equals: null },
                  { pointer: '/a/0', equals: { x: [1, 'y', false] } },
                  { pointer: '/b', matches: 'x', flags: 'i' },
                  { pointer: '/c', notMatches: 'x' },
                ],
              },
            ],
          }),
        ],
      }),
    ],
  ]
  for (const [name, value] of valid) {
    it(`accepts ${name}`, () => {
      assert.deepEqual(errorsOf(value), [])
    })
  }

  const invalid: Array<[string, unknown, string]> = [
    ['a non-object', [], '(root): must be an object'],
    ['null', null, '(root): must be an object'],
    ['missing version', { labels: { a: {} } }, 'version: required'],
    ['version 2', base({ version: 2 }), 'version: unknown version'],
    ['version as string', base({ version: '1' }), 'version: unknown version'],
    ['unknown top-level key', base({ extra: true }), 'extra: unknown key'],
    ['$schema not a string', base({ $schema: 1 }), '$schema: must be a string'],
    ['description not a string', base({ description: [] }), 'description: must be a string'],
    ['bad mode', base({ mode: 'off' }), 'mode: must be one of audit, ask, enforce'],
    ['per-agent subagents', base({ subagents: 'per-agent' }), 'subagents: per-agent is reserved for v1.1'],
    ['other subagents', base({ subagents: 'none' }), 'subagents: must be shared'],
    ['resetOnClear not boolean', base({ resetOnClear: 'yes' }), 'resetOnClear: must be a boolean'],
    ['bad userDeclassify', base({ userDeclassify: 'sometimes' }), 'userDeclassify: must be one of allow, confirm, never'],
    ['bad onUnknownHistory', base({ onUnknownHistory: 'drop' }), 'onUnknownHistory: must be one of ignore, assume-tainted'],
    ['missing labels', { version: 1 }, 'labels: required'],
    ['labels an array', base({ labels: [] }), 'labels: must be an object'],
    ['no labels', base({ labels: {} }), 'labels: must declare at least one label'],
    ['bad label name', base({ labels: { 'a b': {} } }), 'labels.a b: label names are letters, digits and -, 1-32 characters'],
    ['33-character label', base({ labels: { [`${'a'.repeat(33)}`]: {} } }), 'label names'],
    ['label not an object', base({ labels: { a: 'x' } }), 'labels.a: must be an object'],
    ['label unknown key', base({ labels: { a: { color: 'red' } } }), 'labels.a.color: unknown key'],
    ['label description not a string', base({ labels: { a: { description: 1 } } }), 'labels.a.description: must be a string'],
    ['sources not an array', base({ sources: {} }), 'sources: must be an array'],
    ['sinks not an array', base({ sinks: 'x' }), 'sinks: must be an array'],
    ['source not an object', base({ sources: [1] }), 'sources[0]: must be an object'],
    ['source missing id', base({ sources: [{ match: { tool: { exact: 'Read' } }, taints: ['private'] }] }), 'sources[0].id: required'],
    ['source bad id', base({ sources: [sourceRule('a b')] }), 'sources[0].id: must be letters'],
    ['source 65-character id', base({ sources: [sourceRule('a'.repeat(65))] }), 'sources[0].id: must be letters'],
    ['source unknown key', base({ sources: [sourceRule('a', { action: 'deny' })] }), 'sources[0].action: unknown key'],
    ['source missing match', base({ sources: [{ id: 'a', taints: ['private'] }] }), 'sources[0].match: required'],
    ['source bad on', base({ sources: [sourceRule('a', { on: 'later' })] }), 'sources[0].on: must be one of attempt, success'],
    ['source missing taints', base({ sources: [{ id: 'a', match: { tool: { exact: 'Read' } } }] }), 'sources[0].taints: required'],
    ['source empty taints', base({ sources: [sourceRule('a', { taints: [] })] }), 'sources[0].taints: must name at least one label'],
    ['source taints not array', base({ sources: [sourceRule('a', { taints: 'private' })] }), 'sources[0].taints: must be an array of label names'],
    ['source duplicate taint', base({ sources: [sourceRule('a', { taints: ['private', 'private'] })] }), "sources[0].taints[1]: duplicate label 'private'"],
    ['source taint not a name', base({ sources: [sourceRule('a', { taints: [3] })] }), 'sources[0].taints[0]: must be a label name'],
    ['source enabled not boolean', base({ sources: [sourceRule('a', { enabled: 'no' })] }), 'sources[0].enabled: must be a boolean'],
    ['source description not string', base({ sources: [sourceRule('a', { description: 1 })] }), 'sources[0].description: must be a string'],
    ['reference with extra keys', base({ sources: [{ id: 'preset:web', enabled: false, taints: ['private'] }] }), 'sources[0]: a reference to a rule has exactly the keys id and enabled: false'],
    ['reference enabled true', base({ sinks: [{ id: 'user:x', enabled: true }] }), 'sinks[0]: a reference to a rule has exactly the keys id and enabled: false'],
    ['reference without enabled', base({ sinks: [{ id: 'user:x' }] }), 'sinks[0]: a reference'],
    ['reference to an unknown layer', base({ sinks: [{ id: 'org:x', enabled: false }] }), 'sinks[0].id: a reference is <layer>:<id>'],
    ['reference with a bad id', base({ sinks: [{ id: 'user:a b', enabled: false }] }), 'sinks[0].id: a reference is'],
    ['sink missing when', base({ sinks: [{ id: 's', block: [{ tool: { exact: 'Bash' } }] }] }), 'sinks[0].when: required'],
    ['sink when not an object', base({ sinks: [sinkRule('s', { when: [] })] }), 'sinks[0].when: must be an object'],
    ['sink when unknown key', base({ sinks: [sinkRule('s', { when: { noneOf: [] } })] }), 'sinks[0].when.noneOf: unknown key'],
    ['sink when anyOf not array', base({ sinks: [sinkRule('s', { when: { anyOf: 'private' } })] }), 'sinks[0].when.anyOf: must be an array of label names'],
    ['sink when allOf bad name', base({ sinks: [sinkRule('s', { when: { allOf: ['a b'] } })] }), 'sinks[0].when.allOf[0]: must be a label name'],
    ['sink missing block', base({ sinks: [{ id: 's', when: {} }] }), 'sinks[0].block: required'],
    ['sink empty block', base({ sinks: [sinkRule('s', { block: [] })] }), 'sinks[0].block: must hold at least one matcher'],
    ['sink block not array', base({ sinks: [sinkRule('s', { block: { tool: { exact: 'Bash' } } })] }), 'sinks[0].block: must be an array of matchers'],
    ['sink except not array', base({ sinks: [sinkRule('s', { except: {} })] }), 'sinks[0].except: must be an array of matchers'],
    ['sink bad action', base({ sinks: [sinkRule('s', { action: 'block' })] }), 'sinks[0].action: must be one of deny, ask, audit'],
    ['sink reason too long', base({ sinks: [sinkRule('s', { reason: 'r'.repeat(1001) })] }), 'sinks[0].reason: must be at most 1000 characters'],
    ['sink reason not string', base({ sinks: [sinkRule('s', { reason: 1 })] }), 'sinks[0].reason: must be a string'],
    ['sink unknown key', base({ sinks: [sinkRule('s', { taints: ['private'] })] }), 'sinks[0].taints: unknown key'],
    ['sink match key', base({ sinks: [sinkRule('s', { match: {} })] }), 'sinks[0].match: unknown key'],
    ['matcher not an object', base({ sinks: [sinkRule('s', { block: ['Bash'] })] }), 'sinks[0].block[0]: must be an object'],
    ['matcher missing tool', base({ sinks: [sinkRule('s', { block: [{}] })] }), 'sinks[0].block[0].tool: required'],
    ['matcher unknown key', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, args: [] }] })] }), 'sinks[0].block[0].args: unknown key'],
    ['selector with two kinds', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, prefix: 'B' }] })] }), 'sinks[0].block[0].prefix: unknown key'],
    ['selector exact and prefix', base({ sinks: [sinkRule('s'), sinkRule('t', { block: [{ tool: { exact: 'Bash', prefix: 'B' } }] })] }), 'sinks[1].block[0].tool: exactly one of exact, prefix, regex, anyOf'],
    ['selector with no kind', base({ sinks: [sinkRule('s', { block: [{ tool: {} }] })] }), 'sinks[0].block[0].tool: exactly one of exact, prefix, regex, anyOf'],
    ['selector not an object', base({ sinks: [sinkRule('s', { block: [{ tool: 'Bash' }] })] }), 'sinks[0].block[0].tool: must be an object'],
    ['selector unknown key', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash', glob: '*' } }] })] }), 'sinks[0].block[0].tool.glob: unknown key'],
    ['empty exact', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: '' } }] })] }), 'sinks[0].block[0].tool.exact: must be a non-empty string'],
    ['empty prefix', base({ sinks: [sinkRule('s', { block: [{ tool: { prefix: '' } }] })] }), 'sinks[0].block[0].tool.prefix: must be a non-empty string'],
    ['regex not a string', base({ sinks: [sinkRule('s', { block: [{ tool: { regex: 1 } }] })] }), 'sinks[0].block[0].tool.regex: must be a string'],
    ['regex that fails to compile', base({ sinks: [sinkRule('s', { block: [{ tool: { regex: '(' } }] })] }), 'sinks[0].block[0].tool.regex: invalid regex'],
    ['empty anyOf', base({ sinks: [sinkRule('s', { block: [{ tool: { anyOf: [] } }] })] }), 'sinks[0].block[0].tool.anyOf: must be a non-empty array of tool names'],
    ['anyOf with empty name', base({ sinks: [sinkRule('s', { block: [{ tool: { anyOf: ['A', ''] } }] })] }), 'sinks[0].block[0].tool.anyOf[1]: must be a non-empty string'],
    ['flags with exact', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash', flags: 'i' } }] })] }), 'sinks[0].block[0].tool.flags: allowed only with prefix or regex'],
    ['flags with anyOf', base({ sinks: [sinkRule('s', { block: [{ tool: { anyOf: ['A'], flags: 'i' } }] })] }), 'sinks[0].block[0].tool.flags: allowed only with prefix or regex'],
    ['flags other than i', base({ sinks: [sinkRule('s', { block: [{ tool: { regex: 'x', flags: 'g' } }] })] }), "sinks[0].block[0].tool.flags: the only flag is 'i'"],
    ['arguments not an array', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: {} }] })] }), 'sinks[0].block[0].arguments: must be an array'],
    ['predicate not an object', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [1] }] })] }), 'sinks[0].block[0].arguments[0]: must be an object'],
    ['predicate missing pointer', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ exists: true }] }] })] }), 'sinks[0].block[0].arguments[0].pointer: required'],
    ['pointer not a string', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: 1, exists: true }] }] })] }), 'arguments[0].pointer: must be a string'],
    ['pointer without slash', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: 'command', exists: true }] }] })] }), "arguments[0].pointer: must be '' or start with /"],
    ['predicate with no test', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a' }] }] })] }), 'arguments[0]: exactly one of equals, matches, notMatches, exists'],
    ['predicate with two tests', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', exists: true, matches: 'x' }] }] })] }), 'arguments[0]: exactly one of equals, matches, notMatches, exists'],
    ['predicate unknown key', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', exists: true, contains: 'x' }] }] })] }), 'arguments[0].contains: unknown key'],
    ['exists not boolean', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', exists: 'yes' }] }] })] }), 'arguments[0].exists: must be a boolean'],
    ['matches not a string', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', matches: 1 }] }] })] }), 'arguments[0].matches: must be a string'],
    ['matches bad regex', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', matches: '[' }] }] })] }), 'arguments[0].matches: invalid regex'],
    ['notMatches bad regex', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', notMatches: '*' }] }] })] }), 'arguments[0].notMatches: invalid regex'],
    ['flags with equals', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', equals: 'x', flags: 'i' }] }] })] }), 'arguments[0].flags: allowed only with matches or notMatches'],
    ['flags with exists', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', exists: true, flags: 'i' }] }] })] }), 'arguments[0].flags: allowed only with matches or notMatches'],
    ['predicate flag other than i', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', matches: 'x', flags: 'm' }] }] })] }), "arguments[0].flags: the only flag is 'i'"],
    ['equals not JSON', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', equals: () => 1 }] }] })] }), 'arguments[0].equals: must be a JSON value'],
    ['equals undefined', base({ sinks: [sinkRule('s', { block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', equals: undefined }] }] })] }), 'arguments[0].equals: must be a JSON value'],
    ['except matcher invalid', base({ sinks: [sinkRule('s', { except: [{ tool: { regex: ')' } }] })] }), 'sinks[0].except[0].tool.regex: invalid regex'],
    ['duplicate source ids', base({ sources: [sourceRule('a'), sourceRule('a')] }), "sources[1].id: duplicate id 'a' (also sources[0])"],
    ['duplicate id across sources and sinks', base({ sources: [sourceRule('a')], sinks: [sinkRule('a')] }), "sinks[0].id: duplicate id 'a' (also sources[0])"],
  ]
  for (const [name, value, expected] of invalid) {
    it(`rejects ${name}`, () => {
      const errors = errorsOf(value)
      assert.ok(errors.some((e) => e.includes(expected)), `expected an error containing ${JSON.stringify(expected)}, got ${JSON.stringify(errors)}`)
    })
  }

  it('collects every error instead of stopping at the first', () => {
    const errors = errorsOf({
      version: 3,
      mode: 'loud',
      labels: {},
      sinks: [{ id: 's', when: {}, block: [{ tool: { exact: 'Bash', regex: 'x' } }], action: 'x' }],
      extra: 1,
    })
    assert.deepEqual(errors.sort(), [
      'extra: unknown key',
      'labels: must declare at least one label',
      'mode: must be one of audit, ask, enforce',
      'sinks[0].action: must be one of deny, ask, audit',
      'sinks[0].block[0].tool: exactly one of exact, prefix, regex, anyOf',
      'version: unknown version',
    ])
  })

  it('does not check label references', () => {
    assert.deepEqual(errorsOf(base({ sources: [sourceRule('a', { taints: ['elsewhere'] })], sinks: [sinkRule('s', { when: { anyOf: ['other'] } })] })), [])
  })

  it('rejects nested unbounded quantifiers only in the project layer', () => {
    const policy = base({
      sinks: [
        sinkRule('s', {
          block: [{ tool: { regex: '^(a+)+$' }, arguments: [{ pointer: '/command', matches: '(x*)*y' }] }],
        }),
      ],
    })
    assert.deepEqual(errorsOf(policy), [])
    assert.deepEqual(errorsOf(policy, 'user'), [])
    assert.deepEqual(errorsOf(policy, 'project'), [
      'sinks[0].block[0].tool.regex: nested unbounded quantifiers are not allowed in a project policy',
      'sinks[0].block[0].arguments[0].matches: nested unbounded quantifiers are not allowed in a project policy',
    ])
  })

  it('rejects alternation under an unbounded quantifier only in the project layer', () => {
    const shapes = ['(a|aa)+$', '(?:.|.)*X', '(?:[a-z]|[a-y])*X', '(a|b){2,}']
    for (const regex of shapes) {
      const policy = base({ sinks: [sinkRule('s', { block: [{ tool: { regex } }] })] })
      assert.deepEqual(errorsOf(policy), [], regex)
      assert.deepEqual(errorsOf(policy, 'user'), [], regex)
      assert.deepEqual(errorsOf(policy, 'project'), [
        'sinks[0].block[0].tool.regex: alternation under an unbounded quantifier is not allowed in a project policy',
      ], regex)
    }
  })

  it('rejects a project regex longer than 256 characters', () => {
    const policyWith = (length: number) =>
      base({ sources: [sourceRule('s', { match: { tool: { exact: 'Read' }, arguments: [{ pointer: '/p', matches: 'a'.repeat(length) }] } })] })
    assert.deepEqual(errorsOf(policyWith(256), 'project'), [])
    assert.deepEqual(errorsOf(policyWith(257), 'user'), [])
    assert.deepEqual(errorsOf(policyWith(257), 'project'), [
      'sources[0].match.arguments[0].matches: a regex in a project policy must be at most 256 characters',
    ])
  })

  it('rejects a project layer with more than 50 regexes', () => {
    const policyWith = (count: number) =>
      base({
        sinks: [
          sinkRule('s', {
            block: Array.from({ length: count - 1 }, (_, i) => ({ tool: { regex: `^tool${i}$` } })),
            except: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/c', notMatches: '^ls' }] }],
          }),
        ],
      })
    assert.deepEqual(errorsOf(policyWith(50), 'project'), [])
    assert.deepEqual(errorsOf(policyWith(51), 'user'), [])
    assert.deepEqual(errorsOf(policyWith(51), 'project'), ['(root): a project policy may hold at most 50 regexes; this one has 51'])
  })

  it('accepts a legitimate project regex', () => {
    const policy = base({
      sinks: [
        sinkRule('s', {
          block: [
            { tool: { regex: '^mcp__.+__(.*_)?(send|post|reply|forward|create|update|upload|share|schedule|comment|invite)', flags: 'i' } },
            { tool: { exact: 'Read' }, arguments: [{ pointer: '/file_path', matches: '(^|/)([.]env[^/]*|id_(rsa|ed25519|ecdsa)|credentials)$' }] },
          ],
        }),
      ],
    })
    assert.deepEqual(errorsOf(policy, 'project'), [])
    const { layers, warnings } = load({ project: file('project', policy) })
    assert.deepEqual(layers.find((l) => l.layer === 'project')?.status, 'loaded')
    assert.deepEqual(warnings, [])
  })
})

describe('hasQuantifiedAlternation', () => {
  const cases: Array<[string, boolean]> = [
    ['(a|aa)+$', true],
    ['(?:.|.)*X', true],
    ['(?:[a-z]|[a-y])*X', true],
    ['(a|b){2,}', true],
    ['(a|b)+?', true],
    ['((a|b)c)*', false],
    ['((a|b)+c)', true],
    ['(?<n>a|b)*', true],
    ['(a|b)', false],
    ['(a|b)?', false],
    ['(a|b){1,5}', false],
    ['a|b*', false],
    ['(ab)+', false],
    ['([a|b])+', false],
    ['(a\\|b)+', false],
    ['\\(a|b\\)+', false],
    ['^mcp__.+__(.*_)?(send|post|reply)', false],
    ['(^|/)([.]env[^/]*|id_(rsa|ed25519|ecdsa)|credentials)$', false],
    ['', false],
    [')+', false],
  ]
  for (const [source, expected] of cases) {
    it(`${JSON.stringify(source)} -> ${expected}`, () => {
      assert.equal(hasQuantifiedAlternation(source), expected)
    })
  }
})

describe('hasNestedQuantifier', () => {
  const cases: Array<[string, boolean]> = [
    ['(a+)+', true],
    ['(a*)*', true],
    ['(?:x|y+){2,}', true],
    ['^(a+)+$', true],
    ['(a|b+)*', true],
    ['((a+)?)+', true],
    ['((a)+)*', true],
    ['(?<name>a+)+', true],
    ['(?=a+)*b', true],
    ['([a-z]+\\.)+com', true],
    ['(a{1,})*', true],
    ['(a+){1,}', true],
    ['(a+)+?', true],
    ['(.*_)?', false],
    ['(?:[^_]|_(?!_))*?', false],
    ['(a+){2}', false],
    ['(a+){1,5}', false],
    ['(a{2,3})+', false],
    ['(ab)+', false],
    ['(a|b)*', false],
    ['a+b*c?', false],
    ['\\(a+\\)+', false],
    ['\\(a+)+', false],
    ['[(a+)]+', false],
    ['([*+()])+', false],
    ['(a\\*)+', false],
    ['(a\\+)*', false],
    ['(a{,})+', false],
    ['(a{x})+', false],
    ['^mcp__(claude_ai_)?(gmail|google[_-]?mail)[^_]*__(.*_)?(get|read|search|list|fetch|download|history)', false],
    ['^mcp__.+__(.*_)?(send|post|reply|forward|create|update|upload|share|schedule|comment|invite)', false],
    ['(^|/)([.]env[^/]*|id_(rsa|ed25519|ecdsa)|credentials)$', false],
    ['', false],
    ['(', false],
    [')+', false],
  ]
  for (const [source, expected] of cases) {
    it(`${JSON.stringify(source)} -> ${expected}`, () => {
      assert.equal(hasNestedQuantifier(source), expected)
    })
  }
})

describe('resolvePointer', () => {
  const doc = {
    a: { b: [10, { c: 'd' }] },
    'x/y': 1,
    'm~n': 2,
    '': 'empty key',
    n: null,
    f: false,
    arr: ['zero', 'one'],
  }
  const cases: Array<[string, { found: boolean; value?: unknown }]> = [
    ['', { found: true, value: doc }],
    ['/a/b/0', { found: true, value: 10 }],
    ['/a/b/1/c', { found: true, value: 'd' }],
    ['/x~1y', { found: true, value: 1 }],
    ['/m~0n', { found: true, value: 2 }],
    ['/', { found: true, value: 'empty key' }],
    ['/n', { found: true, value: null }],
    ['/f', { found: true, value: false }],
    ['/arr/1', { found: true, value: 'one' }],
    ['/arr/2', { found: false }],
    ['/arr/01', { found: false }],
    ['/arr/-', { found: false }],
    ['/arr/length', { found: false }],
    ['/missing', { found: false }],
    ['/a/b/1/c/d', { found: false }],
    ['/n/x', { found: false }],
    ['/toString', { found: false }],
    ['a', { found: false }],
  ]
  for (const [pointer, expected] of cases) {
    it(JSON.stringify(pointer), () => {
      assert.deepEqual(resolvePointer(doc, pointer), expected)
    })
  }

  it('decodes ~01 as ~1, not /', () => {
    assert.deepEqual(resolvePointer({ '~1': 'tilde-one', '/': 'slash' }, '/~01'), { found: true, value: 'tilde-one' })
  })

  it('treats an undefined property as absent', () => {
    assert.deepEqual(resolvePointer({ a: undefined }, '/a'), { found: false })
  })
})

describe('compileMatcher', () => {
  const cases: Array<[string, Matcher, ToolCall, boolean]> = [
    ['exact hit', { tool: { exact: 'Bash' } }, call('Bash'), true],
    ['exact is case-sensitive', { tool: { exact: 'Bash' } }, call('bash'), false],
    ['prefix hit', { tool: { prefix: 'mcp__slack' } }, call('mcp__slack__send'), true],
    ['prefix case-sensitive miss', { tool: { prefix: 'mcp__slack' } }, call('mcp__Slack__send'), false],
    ['prefix case-insensitive', { tool: { prefix: 'MCP__slack', flags: 'i' } }, call('mcp__Slack__send'), true],
    ['regex unanchored', { tool: { regex: 'send' } }, call('mcp__x__send_message'), true],
    ['regex anchored miss', { tool: { regex: '^send' } }, call('mcp__x__send_message'), false],
    ['regex flags', { tool: { regex: '^MCP__', flags: 'i' } }, call('mcp__x'), true],
    ['anyOf hit', { tool: { anyOf: ['WebFetch', 'WebSearch'] } }, call('WebSearch'), true],
    ['anyOf miss', { tool: { anyOf: ['WebFetch'] } }, call('Web'), false],
    ['equals hit', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', equals: { b: [1, 2] } }] }, call('T', { a: { b: [1, 2] } }), true],
    ['equals key order irrelevant', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', equals: { x: 1, y: 2 } }] }, call('T', { a: { y: 2, x: 1 } }), true],
    ['equals miss on extra key', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', equals: { x: 1 } }] }, call('T', { a: { x: 1, y: 2 } }), false],
    ['equals miss on type', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', equals: 1 }] }, call('T', { a: '1' }), false],
    ['equals null', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', equals: null }] }, call('T', { a: null }), true],
    ['equals absent', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', equals: null }] }, call('T', {}), false],
    ['matches string', { tool: { exact: 'Read' }, arguments: [{ pointer: '/file_path', matches: '\\.env$' }] }, call('Read', { file_path: '/p/.env' }), true],
    ['matches case-insensitive', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', matches: '^curl', flags: 'i' }] }, call('T', { a: 'CURL x' }), true],
    ['matches non-string via JSON', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', matches: '^\\{"k":3\\}$' }] }, call('T', { a: { k: 3 } }), true],
    ['matches number via JSON', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', matches: '^42$' }] }, call('T', { a: 42 }), true],
    ['matches absent', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', matches: '' }] }, call('T', {}), false],
    ['notMatches absent', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', notMatches: 'x' }] }, call('T', {}), true],
    ['notMatches hit', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', notMatches: '^safe' }] }, call('T', { a: 'rm -rf' }), true],
    ['notMatches miss', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', notMatches: '^safe' }] }, call('T', { a: 'safe ls' }), false],
    ['notMatches flags', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', notMatches: '^safe', flags: 'i' }] }, call('T', { a: 'SAFE' }), false],
    ['exists true', { tool: { exact: 'T' }, arguments: [{ pointer: '/a/0', exists: true }] }, call('T', { a: [1] }), true],
    ['exists true absent', { tool: { exact: 'T' }, arguments: [{ pointer: '/a/0', exists: true }] }, call('T', { a: [] }), false],
    ['exists false', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', exists: false }] }, call('T', {}), true],
    ['whole-args pointer', { tool: { exact: 'T' }, arguments: [{ pointer: '', matches: '"url":"https://evil' }] }, call('T', { url: 'https://evil.example' }), true],
    [
      'all predicates must hold',
      { tool: { exact: 'T' }, arguments: [{ pointer: '/a', exists: true }, { pointer: '/b', exists: true }] },
      call('T', { a: 1 }),
      false,
    ],
    ['predicates never rescue a tool miss', { tool: { exact: 'T' }, arguments: [{ pointer: '/a', exists: false }] }, call('U'), false],
  ]
  for (const [name, matcher, input, expected] of cases) {
    it(name, () => {
      assert.equal(compileMatcher(matcher).test(input), expected)
    })
  }

  it('testTool answers yes, maybe or no by tool name', () => {
    assert.equal(compileMatcher({ tool: { exact: 'Bash' } }).testTool('Bash'), 'yes')
    assert.equal(compileMatcher({ tool: { exact: 'Bash' } }).testTool('Read'), 'no')
    assert.equal(compileMatcher({ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', exists: true }] }).testTool('Bash'), 'maybe')
    assert.equal(compileMatcher({ tool: { exact: 'Bash' }, arguments: [{ pointer: '/a', exists: true }] }).testTool('Read'), 'no')
  })

  it('reports names and patterns', () => {
    const exact = compileMatcher({ tool: { exact: 'Bash' } })
    assert.deepEqual([exact.names, exact.patterns], [['Bash'], []])
    const anyOf = compileMatcher({ tool: { anyOf: ['A', 'B', 'A'] } })
    assert.deepEqual([anyOf.names, anyOf.patterns], [['A', 'B'], []])
    const prefix = compileMatcher({ tool: { prefix: 'mcp__slack', flags: 'i' } })
    assert.deepEqual([prefix.names, prefix.patterns], [[], ['mcp__slack…']])
    const regex = compileMatcher({ tool: { regex: '^mcp__.+__send', flags: 'i' } })
    assert.deepEqual([regex.names, regex.patterns], [[], ['/^mcp__.+__send/i']])
  })

  it('runs a regex on text up to 100,000 characters', () => {
    const matcher = compileMatcher({ tool: { exact: 'T' }, arguments: [{ pointer: '/a', matches: 'x$' }] })
    assert.equal(matcher.test(call('T', { a: `${'a'.repeat(99_999)}x` })), true)
    assert.equal(matcher.test(call('T', { a: 'a'.repeat(100_000) })), false)
    for (const role of ['block', 'source', 'except'] as const) {
      const negative = compileMatcher({ tool: { exact: 'T' }, arguments: [{ pointer: '/a', notMatches: 'x$' }] }, role)
      assert.equal(negative.test(call('T', { a: `${'a'.repeat(99_999)}x` })), false, role)
    }
  })

  it('fails closed on text over 100,000 characters by role', () => {
    const long = { a: `${'a'.repeat(100_000)}x`, b: 'b'.repeat(100_001) }
    const cases: Array<[Matcher['arguments'], 'block' | 'source' | 'except' | undefined, boolean]> = [
      [[{ pointer: '/a', matches: 'nothing-here' }], undefined, true],
      [[{ pointer: '/a', matches: 'nothing-here' }], 'block', true],
      [[{ pointer: '/a', notMatches: 'x$' }], 'block', true],
      [[{ pointer: '/a', matches: 'nothing-here' }], 'source', true],
      [[{ pointer: '/a', notMatches: 'x$' }], 'source', true],
      [[{ pointer: '/a', matches: 'x$' }], 'except', false],
      [[{ pointer: '/a', notMatches: 'nothing-here' }], 'except', false],
      [[{ pointer: '', matches: '^\\{' }], 'except', false],
      [[{ pointer: '/b', matches: '^b' }], 'except', false],
    ]
    for (const [args, role, expected] of cases) {
      const matcher = compileMatcher({ tool: { exact: 'T' }, arguments: args }, role)
      assert.equal(matcher.test(call('T', long)), expected, JSON.stringify([args, role]))
    }
  })

  it('compiles sink and source matchers with their role', () => {
    const big = { command: `${'a'.repeat(100_000)} curl` }
    const { policy } = load({
      user: file(
        'user',
        base({
          sources: [sourceRule('src', { match: { tool: { exact: 'Bash' }, arguments: [{ pointer: '/command', matches: 'never' }] } })],
          sinks: [
            sinkRule('snk', {
              block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/command', matches: 'never' }] }],
              except: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/command', notMatches: 'curl' }] }],
            }),
          ],
        }),
      ),
    })
    assert.deepEqual(matchSources(policy, call('Bash', big), 'attempt').map((s) => s.id), ['user:src'])
    assert.equal(evaluateSinks(policy, call('Bash', big), set('private')).action, 'deny')
    assert.equal(evaluateSinks(policy, call('Bash', { command: 'ls' }), set('private')).action, 'allow')
  })
})

describe('loadPolicy: layers', () => {
  it('loads the example as a user layer with namespaced ids', () => {
    const loaded = load({ user: file('user', EXAMPLE) })
    assert.equal(loaded.lockdown, null)
    assert.deepEqual(loaded.warnings, [])
    assert.deepEqual(
      loaded.policy.sources.map((s) => [s.id, s.layer, s.on, s.trusted]),
      [
        ['user:gmail-read', 'user', 'attempt', true],
        ['user:web-content', 'user', 'success', true],
        ['user:secret-files', 'user', 'attempt', true],
      ],
    )
    assert.deepEqual(loaded.policy.sinks.map((s) => [s.id, s.declared, s.action]), [
      ['user:no-shell-after-mail', 'deny', 'deny'],
      ['user:outbound-after-untrusted-private', 'ask', 'ask'],
    ])
    assert.deepEqual(loaded.layers, [
      { layer: 'preset', path: null, status: 'absent', rules: 0 },
      { layer: 'user', path: '/user.json', status: 'loaded', rules: 5 },
    ])
    assert.deepEqual(loaded.policy.labels.private, { description: 'Data the user owns: mail, documents, chats', layer: 'user' })
  })

  it('reports absent files with their path and omits unconfigured layers', () => {
    const loaded = load({ managed: null, user: { layer: 'user', path: '/u.json', text: null }, project: { layer: 'project', path: '/p.json', text: null } })
    assert.equal(loaded.lockdown, null)
    assert.deepEqual(loaded.layers, [
      { layer: 'preset', path: null, status: 'absent', rules: 0 },
      { layer: 'user', path: '/u.json', status: 'absent', rules: 0 },
      { layer: 'project', path: '/p.json', status: 'absent', rules: 0 },
    ])
    assert.deepEqual(loaded.policy.sinks, [])
  })

  it('locks down when the configured managed policy file does not exist', () => {
    const loaded = load({ managed: { layer: 'managed', path: '/etc/tg.json', text: null } }, PRESETS)
    assert.equal(loaded.lockdown, 'managed policy /etc/tg.json: file not found')
    assert.deepEqual(loaded.layers.find((l) => l.layer === 'managed'), {
      layer: 'managed',
      path: '/etc/tg.json',
      status: 'invalid',
      rules: 0,
      error: 'file not found',
    })
    assert.ok(loaded.policy.sinks.some((s) => s.id === 'preset:outbound'))
  })

  it('orders rules managed, user, project, preset', () => {
    const loaded = load(
      {
        preset: 'trifecta',
        managed: file('managed', base({ sinks: [sinkRule('m')] })),
        user: file('user', base({ sinks: [sinkRule('u')] })),
        project: file('project', base({ sinks: [sinkRule('p')] })),
      },
      PRESETS,
    )
    assert.deepEqual(loaded.policy.sinks.map((s) => [s.id, s.trusted]), [
      ['managed:m', true],
      ['user:u', true],
      ['project:p', false],
      ['preset:outbound', true],
    ])
    assert.deepEqual(loaded.layers.map((l) => [l.layer, l.status, l.rules]), [
      ['preset', 'loaded', 2],
      ['managed', 'loaded', 1],
      ['user', 'loaded', 1],
      ['project', 'loaded', 1],
    ])
    assert.equal(loaded.layers[0]?.path, 'presets/trifecta.json')
  })

  it('takes the first label description in managed, user, project, preset order', () => {
    const loaded = load(
      {
        preset: 'trifecta',
        user: file('user', { version: 1, labels: { private: { description: 'from user' }, mine: {} } }),
        project: file('project', { version: 1, labels: { private: { description: 'from project' }, repo: { description: 'r' } } }),
      },
      PRESETS,
    )
    assert.deepEqual(loaded.policy.labels, {
      private: { description: 'from user', layer: 'user' },
      mine: { layer: 'user' },
      repo: { description: 'r', layer: 'project' },
      untrusted: { layer: 'preset' },
      secret: { layer: 'preset' },
    })
    assert.deepEqual(allLabels(loaded.policy), ['mine', 'private', 'repo', 'secret', 'untrusted'])
  })

  it('lets a layer reference labels declared by another layer', () => {
    const loaded = load({
      user: file('user', { version: 1, labels: { secret: {} } }),
      project: file('project', { version: 1, labels: { repo: {} }, sinks: [sinkRule('p', { when: { allOf: ['secret', 'repo'] } })] }),
    })
    assert.equal(loaded.lockdown, null)
    assert.deepEqual(loaded.policy.sinks.map((s) => s.id), ['project:p'])
  })

  it('carries input warnings first', () => {
    const loaded = load({ warnings: ['first'], project: file('project', '{') })
    assert.equal(loaded.warnings[0], 'first')
    assert.match(loaded.warnings[1] ?? '', /^project policy \/project.json dropped: invalid JSON: /)
  })
})

describe('loadPolicy: lockdown and dropped layers', () => {
  const strictSinkIds = ['preset:outbound']

  it('locks down on an unreadable managed setting, with the strict preset sinks present', () => {
    const loaded = load({ managedReadError: 'EACCES', user: file('user', EXAMPLE) }, PRESETS)
    assert.equal(loaded.lockdown, 'cannot read managed settings: EACCES')
    assert.equal(loaded.policy.mode, 'enforce')
    assert.deepEqual(loaded.policy.sinks.map((s) => s.id), ['user:no-shell-after-mail', 'user:outbound-after-untrusted-private', ...strictSinkIds])
    assert.deepEqual(loaded.policy.sources.map((s) => s.id), ['user:gmail-read', 'user:web-content', 'user:secret-files', 'preset:web'])
    assert.ok(allLabels(loaded.policy).includes('lockdown'))
  })

  const lockdownCases: Array<[string, Partial<LoadInput>, RegExp]> = [
    ['malformed managed JSON', { managed: file('managed', '{nope') }, /^managed policy \/managed.json: invalid JSON: /],
    ['invalid managed policy', { managed: file('managed', base({ version: 2 })) }, /^managed policy \/managed.json: version: unknown version$/],
    ['malformed user JSON', { user: file('user', '[') }, /^user policy \/user.json: invalid JSON: /],
    ['invalid user policy', { user: file('user', base({ sinks: [sinkRule('s', { block: [] })] })) }, /^user policy \/user.json: sinks\[0\].block: must hold at least one matcher$/],
    ['unreadable user file', { user: { layer: 'user', path: '/user.json', text: null, readError: 'EISDIR' } }, /^user policy \/user.json: cannot read: EISDIR$/],
    ['user unknown label', { user: file('user', base({ sinks: [sinkRule('s', { when: { anyOf: ['private', 'ghost'] } })] })) }, /^user policy \/user.json: unknown label 'ghost' at sinks\[0\].when.anyOf\[1\]$/],
    ['managed unknown taint', { managed: file('managed', base({ sources: [sourceRule('a', { taints: ['nope'] })] })) }, /^managed policy \/managed.json: unknown label 'nope' at sources\[0\].taints\[0\]$/],
  ]
  for (const [name, input, expected] of lockdownCases) {
    it(`locks down on ${name}`, () => {
      const loaded = load({ preset: 'trifecta', ...input }, PRESETS)
      assert.match(loaded.lockdown ?? '', expected)
      const bad = loaded.layers.find((l) => l.status === 'invalid')
      assert.ok(bad, 'the bad layer is reported invalid')
      assert.equal(bad.rules, 0)
      assert.ok(loaded.policy.sinks.some((s) => s.id === 'preset:outbound'))
      assert.equal(loaded.policy.mode, 'enforce')
    })
  }

  it('locks down on an invalid preset', () => {
    const broken = { ...TRIFECTA, sinks: [{ id: 'x', when: {}, block: [] }] } as unknown as PolicyFile
    const loaded = load({ preset: 'trifecta' }, { ...PRESETS, trifecta: broken })
    assert.equal(loaded.lockdown, 'preset policy presets/trifecta.json: sinks[0].block: must hold at least one matcher')
    assert.deepEqual(loaded.layers, [{ layer: 'preset', path: 'presets/trifecta.json', status: 'invalid', rules: 0, error: 'sinks[0].block: must hold at least one matcher' }])
    assert.deepEqual(loaded.policy.sinks.map((s) => s.id), ['preset:outbound'])
  })

  it('keeps declared actions in lockdown even when a valid layer asks for audit', () => {
    const loaded = load(
      {
        managedReadError: 'boom',
        user: file('user', base({ mode: 'audit', sinks: [sinkRule('a', { action: 'ask' }), sinkRule('d')] })),
      },
      PRESETS,
    )
    assert.equal(loaded.policy.mode, 'enforce')
    assert.deepEqual(loaded.policy.sinks.map((s) => [s.id, s.action]), [
      ['user:a', 'ask'],
      ['user:d', 'deny'],
      ['preset:outbound', 'deny'],
    ])
  })

  it('does not duplicate strict rules when the strict preset is loaded', () => {
    const loaded = load({ preset: 'strict', managedReadError: 'boom' }, PRESETS)
    assert.deepEqual(loaded.policy.sinks.map((s) => s.id), ['preset:outbound'])
    assert.deepEqual(loaded.policy.sources.map((s) => s.id), ['preset:web'])
  })

  it('restores a disabled strict rule in lockdown', () => {
    const loaded = load(
      { preset: 'strict', managedReadError: 'boom', user: file('user', base({ sinks: [{ id: 'preset:outbound', enabled: false }] })) },
      PRESETS,
    )
    assert.deepEqual(loaded.policy.sinks.map((s) => s.id), ['preset:outbound'])
  })

  it('reports the first lockdown cause', () => {
    const loaded = load({ managedReadError: 'one', user: file('user', '{') }, PRESETS)
    assert.equal(loaded.lockdown, 'cannot read managed settings: one')
  })

  const droppedCases: Array<[string, LayerText, RegExp]> = [
    ['malformed JSON', file('project', '{'), /^project policy \/project.json dropped: invalid JSON: /],
    ['schema error', file('project', base({ mode: 'off' })), /^project policy \/project.json dropped: mode: must be one of audit, ask, enforce$/],
    ['unknown label', file('project', base({ sources: [sourceRule('a', { taints: ['zzz'] })] })), /dropped: unknown label 'zzz' at sources\[0\].taints\[0\]$/],
    ['ReDoS regex', file('project', base({ sinks: [sinkRule('s', { block: [{ tool: { regex: '(a+)+' } }] })] })), /dropped: sinks\[0\].block\[0\].tool.regex: nested unbounded quantifiers/],
    ['read error', { layer: 'project', path: '/project.json', text: null, readError: 'EPERM' }, /dropped: cannot read: EPERM$/],
  ]
  for (const [name, project, expected] of droppedCases) {
    it(`drops a project layer with ${name}, never locking down`, () => {
      const loaded = load({ user: file('user', EXAMPLE), project }, PRESETS)
      assert.equal(loaded.lockdown, null)
      assert.equal(loaded.warnings.length, 1)
      assert.match(loaded.warnings[0] ?? '', expected)
      const status = loaded.layers.find((l) => l.layer === 'project')
      assert.equal(status?.status, 'dropped')
      assert.equal(status?.rules, 0)
      assert.ok(status?.error)
      assert.equal(loaded.policy.sinks.length, 2)
      assert.ok(loaded.policy.sinks.every((s) => s.layer === 'user'))
    })
  }

  it('locks down when a user layer relies on a label only a dropped project declared', () => {
    const loaded = load({
      user: file('user', base({ sinks: [sinkRule('s', { when: { anyOf: ['repo'] } })] })),
      project: file('project', { version: 1, labels: { repo: {} }, mode: 'nope' }),
    })
    assert.match(loaded.lockdown ?? '', /^user policy \/user.json: unknown label 'repo'/)
  })
})

describe('loadPolicy: disabling', () => {
  it('a rule with enabled: false disables itself in any layer', () => {
    const loaded = load({
      user: file('user', base({ sinks: [sinkRule('off', { enabled: false }), sinkRule('on')] })),
      project: file('project', base({ sources: [sourceRule('quiet', { enabled: false })] })),
    })
    assert.deepEqual(loaded.policy.sinks.map((s) => s.id), ['user:on'])
    assert.deepEqual(loaded.policy.sources, [])
    assert.deepEqual(loaded.warnings, [])
    assert.deepEqual(loaded.layers.map((l) => [l.layer, l.rules]), [
      ['preset', 0],
      ['user', 1],
      ['project', 0],
    ])
  })

  it('acceptance 11: a project policy cannot disable a managed rule', () => {
    const loaded = load({
      managed: file('managed', base({ sinks: [sinkRule('gmail-bash')] })),
      project: file('project', base({ sinks: [{ id: 'managed:gmail-bash', enabled: false }] })),
    })
    assert.deepEqual(loaded.policy.sinks.map((s) => s.id), ['managed:gmail-bash'])
    assert.deepEqual(loaded.warnings, ['project policy cannot disable managed:gmail-bash; the rule stays on'])
    assert.equal(loaded.lockdown, null)
  })

  type Case = [actor: 'managed' | 'user' | 'project', target: 'preset' | 'managed' | 'user' | 'project', presetFromManaged: boolean, allowed: boolean]
  const permissions: Case[] = [
    ['managed', 'preset', false, true],
    ['managed', 'preset', true, true],
    ['managed', 'user', false, true],
    ['managed', 'project', false, true],
    ['managed', 'managed', false, true],
    ['user', 'preset', false, true],
    ['user', 'preset', true, false],
    ['user', 'project', false, true],
    ['user', 'managed', false, false],
    ['user', 'user', false, true],
    ['project', 'preset', false, false],
    ['project', 'managed', false, false],
    ['project', 'user', false, false],
    ['project', 'project', false, true],
  ]
  for (const [actor, target, presetFromManaged, allowed] of permissions) {
    it(`${actor} ${allowed ? 'may' : 'may not'} disable a ${target} rule${presetFromManaged ? ' (preset from managed)' : ''}`, () => {
      const targetPolicy = base({ sinks: [sinkRule('t')] })
      const actorRules = base({ sinks: [{ id: `${target}:t`, enabled: false }] })
      const input: Partial<LoadInput> = { preset: 'trifecta', presetFromManaged }
      const presets = { ...PRESETS, trifecta: target === 'preset' ? (targetPolicy as unknown as PolicyFile) : null }
      const layers: Record<string, unknown[]> = {}
      if (target !== 'preset') layers[target] = [targetPolicy]
      ;(layers[actor] ??= []).push(actorRules)
      for (const [layer, parts] of Object.entries(layers)) {
        const merged = parts.length === 1 ? parts[0] : base({ sinks: [sinkRule('t'), { id: `${target}:t`, enabled: false }] })
        ;(input as Record<string, unknown>)[layer] = file(layer as LayerText['layer'], merged)
      }
      const loaded = load(input, presets)
      assert.equal(loaded.lockdown, null)
      const present = loaded.policy.sinks.some((s) => s.id === `${target}:t`)
      assert.equal(present, !allowed)
      if (allowed) assert.deepEqual(loaded.warnings, [])
      else assert.deepEqual(loaded.warnings, [`${actor} policy cannot disable ${target}:t; the rule stays on`])
    })
  }

  it('user disables a preset source and sink unless the preset came from managed', () => {
    const user = file('user', base({ sources: [{ id: 'preset:web', enabled: false }], sinks: [{ id: 'preset:outbound', enabled: false }] }))
    const free = load({ preset: 'trifecta', user }, PRESETS)
    assert.deepEqual([free.policy.sources.length, free.policy.sinks.length], [0, 0])
    assert.deepEqual(free.layers.find((l) => l.layer === 'preset')?.rules, 0)
    const floored = load({ preset: 'trifecta', presetFromManaged: true, user }, PRESETS)
    assert.deepEqual(floored.policy.sources.map((s) => s.id), ['preset:web'])
    assert.deepEqual(floored.policy.sinks.map((s) => s.id), ['preset:outbound'])
    assert.deepEqual(floored.warnings, [
      'user policy cannot disable preset:web; the rule stays on',
      'user policy cannot disable preset:outbound; the rule stays on',
    ])
  })

  it('warns about a reference to a rule that does not exist', () => {
    const loaded = load({ user: file('user', base({ sinks: [{ id: 'preset:ghost', enabled: false }] })) })
    assert.deepEqual(loaded.warnings, ['user policy refers to unknown rule preset:ghost; nothing disabled'])
  })

  it('a reference may name a sink from the sources list', () => {
    const loaded = load({ user: file('user', base({ sinks: [sinkRule('s')], sources: [{ id: 'user:s', enabled: false }] })) })
    assert.deepEqual(loaded.policy.sinks, [])
  })
})

describe('loadPolicy: globals', () => {
  const globalsOf = (layers: Partial<Record<'preset' | 'managed' | 'user' | 'project', Record<string, unknown>>>) => {
    const input: Partial<LoadInput> = { preset: layers.preset ? 'trifecta' : 'none' }
    for (const name of ['managed', 'user', 'project'] as const) {
      const extra = layers[name]
      if (extra) input[name] = file(name, base(extra))
    }
    const presets = { ...PRESETS, trifecta: layers.preset ? (base(layers.preset) as unknown as PolicyFile) : null }
    return load(input, presets)
  }

  it('defaults to enforce, confirm, assume-tainted, resetOnClear true', () => {
    const { policy, warnings } = globalsOf({ user: {} })
    assert.deepEqual(
      [policy.mode, policy.userDeclassify, policy.userDeclassifyFrom, policy.onUnknownHistory, policy.resetOnClear, policy.subagents],
      ['enforce', 'confirm', 'default', 'assume-tainted', true, 'shared'],
    )
    assert.deepEqual(warnings, [])
  })

  const strictCases: Array<[string, Parameters<typeof globalsOf>[0], { mode?: string; userDeclassify?: string; from?: string; onUnknownHistory?: string }]> = [
    ['a single audit layer', { user: { mode: 'audit' } }, { mode: 'audit' }],
    ['ask beats audit', { user: { mode: 'audit' }, project: { mode: 'ask' } }, { mode: 'ask' }],
    ['enforce beats ask', { managed: { mode: 'ask' }, preset: { mode: 'enforce' } }, { mode: 'enforce' }],
    ['project can tighten mode', { user: { mode: 'audit' }, project: { mode: 'enforce' } }, { mode: 'enforce' }],
    ['never beats confirm', { user: { userDeclassify: 'confirm' }, project: { userDeclassify: 'never' } }, { userDeclassify: 'never', from: 'project' }],
    ['allow alone', { user: { userDeclassify: 'allow' } }, { userDeclassify: 'allow', from: 'user' }],
    ['most trusted layer holding the winner', { preset: { userDeclassify: 'never' }, user: { userDeclassify: 'never' }, project: { userDeclassify: 'never' } }, { userDeclassify: 'never', from: 'user' }],
    ['managed wins the tie', { managed: { userDeclassify: 'confirm' }, user: { userDeclassify: 'confirm' } }, { userDeclassify: 'confirm', from: 'managed' }],
    ['preset when only it sets it', { preset: { userDeclassify: 'allow' } }, { userDeclassify: 'allow', from: 'preset' }],
    ['ignore alone', { user: { onUnknownHistory: 'ignore' } }, { onUnknownHistory: 'ignore' }],
    ['assume-tainted beats ignore', { user: { onUnknownHistory: 'ignore' }, project: { onUnknownHistory: 'assume-tainted' } }, { onUnknownHistory: 'assume-tainted' }],
  ]
  for (const [name, layers, expected] of strictCases) {
    it(name, () => {
      const { policy } = globalsOf(layers)
      if (expected.mode) assert.equal(policy.mode, expected.mode)
      if (expected.userDeclassify) assert.equal(policy.userDeclassify, expected.userDeclassify)
      if (expected.from) assert.equal(policy.userDeclassifyFrom, expected.from)
      if (expected.onUnknownHistory) assert.equal(policy.onUnknownHistory, expected.onUnknownHistory)
    })
  }

  it('a project layer alone cannot lower mode, userDeclassify or onUnknownHistory below the defaults', () => {
    const { policy, warnings } = globalsOf({ project: { mode: 'audit', userDeclassify: 'allow', onUnknownHistory: 'ignore' } })
    assert.deepEqual(
      [policy.mode, policy.userDeclassify, policy.userDeclassifyFrom, policy.onUnknownHistory],
      ['enforce', 'confirm', 'default', 'assume-tainted'],
    )
    assert.deepEqual(warnings, [
      'project policy cannot lower mode; the value is ignored',
      'project policy cannot lower userDeclassify; the value is ignored',
      'project policy cannot lower onUnknownHistory; the value is ignored',
    ])
  })

  it('a project layer cannot lower a value a trusted layer set', () => {
    const { policy } = globalsOf({ user: { mode: 'ask', userDeclassify: 'never' }, project: { mode: 'audit', userDeclassify: 'allow' } })
    assert.equal(policy.mode, 'ask')
    assert.equal(policy.userDeclassify, 'never')
    assert.equal(policy.userDeclassifyFrom, 'user')
  })

  const weakUser = { mode: 'audit', userDeclassify: 'allow', onUnknownHistory: 'ignore', sinks: [sinkRule('mine', { when: {} })] }
  const floorWarnings = [
    'user policy cannot lower mode below the managed floor; the value is ignored',
    'user policy cannot lower userDeclassify below the managed floor; the value is ignored',
    'user policy cannot lower onUnknownHistory below the managed floor; the value is ignored',
  ]

  it('without a managed floor a user layer may lower the globals', () => {
    const { policy, warnings } = load({ preset: 'trifecta', user: file('user', base(weakUser)) }, PRESETS)
    assert.deepEqual([policy.mode, policy.userDeclassify, policy.onUnknownHistory], ['audit', 'allow', 'ignore'])
    assert.deepEqual(warnings, [])
  })

  for (const [name, input] of [
    ['managedFloor', { managedFloor: true }],
    ['presetFromManaged', { presetFromManaged: true }],
  ] as const) {
    it(`with ${name} a user layer cannot lower the globals below the managed floor`, () => {
      const { policy, warnings } = load({ preset: 'trifecta', ...input, user: file('user', base(weakUser)) }, PRESETS)
      assert.deepEqual(
        [policy.mode, policy.userDeclassify, policy.userDeclassifyFrom, policy.onUnknownHistory],
        ['enforce', 'confirm', 'default', 'assume-tainted'],
      )
      assert.deepEqual(warnings, floorWarnings)
      assert.deepEqual(policy.sinks.map((s) => `${s.id}:${s.action}`), ['user:mine:deny', 'preset:outbound:ask'])
      assert.equal(evaluateSinks(policy, call('Bash'), set('private', 'untrusted')).action, 'deny')
    })
  }

  it('with a managed floor the floor comes from the managed and preset layers, and the user may tighten', () => {
    const floorOf = (layers: { managed?: Record<string, unknown>; preset?: Record<string, unknown>; user: Record<string, unknown> }) =>
      load(
        {
          preset: 'trifecta',
          managedFloor: true,
          user: file('user', base(layers.user)),
          ...(layers.managed ? { managed: file('managed', base(layers.managed)) } : {}),
        },
        { ...PRESETS, trifecta: base(layers.preset ?? {}) as unknown as PolicyFile },
      )
    const lowManaged = floorOf({ managed: { mode: 'audit', userDeclassify: 'allow' }, user: { mode: 'ask' } })
    assert.deepEqual([lowManaged.policy.mode, lowManaged.policy.userDeclassify, lowManaged.policy.userDeclassifyFrom], ['ask', 'allow', 'managed'])
    assert.deepEqual(lowManaged.warnings, [])
    const lowPreset = floorOf({ preset: { onUnknownHistory: 'ignore' }, user: { onUnknownHistory: 'ignore' } })
    assert.equal(lowPreset.policy.onUnknownHistory, 'ignore')
    assert.deepEqual(lowPreset.warnings, [])
    const belowManaged = floorOf({ managed: { mode: 'ask' }, user: { mode: 'audit', userDeclassify: 'never' } })
    assert.deepEqual([belowManaged.policy.mode, belowManaged.policy.userDeclassify, belowManaged.policy.userDeclassifyFrom], ['ask', 'never', 'user'])
    assert.deepEqual(belowManaged.warnings, [floorWarnings[0]])
  })

  it('with a managed floor a project layer still only tightens', () => {
    const { policy, warnings } = load({
      managedFloor: true,
      managed: file('managed', base({ mode: 'ask' })),
      user: file('user', base({ mode: 'ask' })),
      project: file('project', base({ mode: 'audit', userDeclassify: 'never' })),
    })
    assert.deepEqual([policy.mode, policy.userDeclassify, policy.userDeclassifyFrom], ['ask', 'never', 'project'])
    assert.deepEqual(warnings, ['project policy cannot lower mode; the value is ignored'])
  })

  const resetCases: Array<[string, Parameters<typeof globalsOf>[0], boolean, number]> = [
    ['managed value wins', { managed: { resetOnClear: false }, user: { resetOnClear: true } }, false, 0],
    ['user value without managed', { user: { resetOnClear: false } }, false, 0],
    ['managed true over user false', { managed: { resetOnClear: true }, user: { resetOnClear: false } }, true, 0],
    ['project value ignored with a warning', { user: {}, project: { resetOnClear: false } }, true, 1],
    ['preset value ignored', { preset: { resetOnClear: false } }, true, 0],
  ]
  for (const [name, layers, expected, warningCount] of resetCases) {
    it(`resetOnClear: ${name}`, () => {
      const loaded = globalsOf(layers)
      assert.equal(loaded.policy.resetOnClear, expected)
      assert.equal(loaded.warnings.length, warningCount)
      if (warningCount) assert.equal(loaded.warnings[0], 'project policy cannot set resetOnClear; the value is ignored')
    })
  }

  it('mode ask turns deny into ask; mode audit turns everything into audit', () => {
    const sinks = [sinkRule('d'), sinkRule('a', { action: 'ask' }), sinkRule('u', { action: 'audit' })]
    const byMode = (mode: string) =>
      load({ user: file('user', base({ mode, sinks })) }).policy.sinks.map((s) => `${s.declared}->${s.action}`)
    assert.deepEqual(byMode('enforce'), ['deny->deny', 'ask->ask', 'audit->audit'])
    assert.deepEqual(byMode('ask'), ['deny->ask', 'ask->ask', 'audit->audit'])
    assert.deepEqual(byMode('audit'), ['deny->audit', 'ask->audit', 'audit->audit'])
  })

  it('writes a default reason from the label condition', () => {
    const loaded = load({
      user: file(
        'user',
        base({
          sinks: [
            sinkRule('any', { when: { anyOf: ['private', 'secret'] } }),
            sinkRule('all', { when: { allOf: ['private', 'untrusted'] } }),
            sinkRule('three', { when: { anyOf: ['private', 'untrusted', 'secret'] } }),
            sinkRule('both', { when: { anyOf: ['secret'], allOf: ['private', 'untrusted'] } }),
            sinkRule('always', { when: {} }),
            sinkRule('given', { reason: 'Custom.' }),
          ],
        }),
      ),
    })
    assert.deepEqual(loaded.policy.sinks.map((s) => s.reason), [
      'This tool is blocked while the session holds private or secret content.',
      'This tool is blocked while the session holds private and untrusted content.',
      'This tool is blocked while the session holds private, untrusted or secret content.',
      'This tool is blocked while the session holds private and untrusted content together with secret content.',
      'This tool is blocked by TaintGuard policy.',
      'Custom.',
    ])
  })

  it('carries descriptions onto compiled rules', () => {
    const loaded = load({ user: file('user', base({ sources: [sourceRule('s', { description: 'src' })], sinks: [sinkRule('k', { description: 'snk' })] })) })
    assert.equal(loaded.policy.sources[0]?.description, 'src')
    assert.equal(loaded.policy.sinks[0]?.description, 'snk')
  })
})

describe('evaluation', () => {
  const policy = load({ user: file('user', EXAMPLE) }).policy

  it('isSinkActive follows anyOf, allOf, both and neither', () => {
    const sink = (anyOf: string[], allOf: string[]) => ({ when: { anyOf, allOf } }) as unknown as CompiledSink
    const cases: Array<[string[], string[], string[], boolean]> = [
      [[], [], [], true],
      [['a', 'b'], [], ['b'], true],
      [['a', 'b'], [], ['c'], false],
      [[], ['a', 'b'], ['a'], false],
      [[], ['a', 'b'], ['a', 'b', 'c'], true],
      [['c'], ['a', 'b'], ['a', 'b'], false],
      [['c'], ['a', 'b'], ['a', 'c'], false],
      [['c'], ['a', 'b'], ['a', 'b', 'c'], true],
    ]
    for (const [anyOf, allOf, labels, expected] of cases) {
      assert.equal(isSinkActive(sink(anyOf, allOf), new Set(labels)), expected, JSON.stringify([anyOf, allOf, labels]))
    }
  })

  it('allows everything on a clean session', () => {
    for (const tool of ['Bash', 'WebFetch', 'mcp__slack__send_message']) {
      assert.deepEqual(evaluateSinks(policy, call(tool), set()), { action: 'allow', matches: [] })
    }
  })

  it('denies Bash after private mail', () => {
    const d = evaluateSinks(policy, call('Bash', { command: 'ls' }), set('private', 'untrusted'))
    assert.equal(d.action, 'deny')
    assert.equal(d.primary?.sink.id, 'user:no-shell-after-mail')
    assert.equal(d.primary?.sink.reason, 'Bash is disabled because this session has read private mail or secrets.')
  })

  it('acceptance 6: a call matching a sink and its except is allowed', () => {
    const labels = set('private', 'untrusted')
    assert.equal(evaluateSinks(policy, call('mcp__claude_ai_Gmail__gmail_create_draft'), labels).action, 'allow')
    assert.equal(evaluateSinks(policy, call('mcp__gmail__create_draft'), labels).action, 'allow')
    assert.equal(evaluateSinks(policy, call('mcp__gmail__send_message'), labels).action, 'ask')
  })

  it('acceptance 7: allOf needs both labels', () => {
    assert.equal(evaluateSinks(policy, call('WebFetch'), set('private')).action, 'allow')
    assert.equal(evaluateSinks(policy, call('WebFetch'), set('untrusted')).action, 'allow')
    assert.equal(evaluateSinks(policy, call('WebFetch'), set('private', 'untrusted')).action, 'ask')
  })

  it('takes the strictest action and lists matches strictest first, stable', () => {
    const p = load({
      user: file(
        'user',
        base({
          sinks: [
            sinkRule('audit1', { action: 'audit', when: {} }),
            sinkRule('ask1', { action: 'ask', when: {} }),
            sinkRule('deny1', { when: {} }),
            sinkRule('ask2', { action: 'ask', when: {} }),
            sinkRule('deny2', { when: {} }),
            sinkRule('inactive', { when: { anyOf: ['secret'] } }),
            sinkRule('other', { when: {}, block: [{ tool: { exact: 'Read' } }] }),
          ],
        }),
      ),
    }).policy
    const d = evaluateSinks(p, call('Bash'), set())
    assert.equal(d.action, 'deny')
    assert.deepEqual(d.matches.map((m) => `${m.sink.id}:${m.action}`), ['user:deny1:deny', 'user:deny2:deny', 'user:ask1:ask', 'user:ask2:ask', 'user:audit1:audit'])
    assert.equal(d.primary, d.matches[0])
    const auditOnly = evaluateSinks(load({ user: file('user', base({ sinks: [sinkRule('a', { action: 'audit', when: {} })] })) }).policy, call('Bash'), set())
    assert.equal(auditOnly.action, 'audit')
  })

  it('among equal actions ranks trusted sinks before project sinks', () => {
    const p = load(
      {
        preset: 'trifecta',
        project: file('project', base({ sinks: [sinkRule('repo', { action: 'ask', reason: 'Approve this, it is safe.' })] })),
      },
      PRESETS,
    ).policy
    assert.deepEqual(p.sinks.map((s) => s.id), ['project:repo', 'preset:outbound'])
    const labels = set('private', 'untrusted')
    const d = evaluateSinks(p, call('Bash'), labels)
    assert.equal(d.action, 'ask')
    assert.deepEqual(d.matches.map((m) => m.sink.id), ['preset:outbound', 'project:repo'])
    assert.equal(d.primary?.sink.id, 'preset:outbound')
    const safe = failSafeDecision(p, call('Bash'), labels)
    assert.deepEqual(safe.matches.map((m) => m.sink.id), ['preset:outbound', 'project:repo'])
  })

  it('judges argument predicates on sinks', () => {
    const p = load({
      user: file(
        'user',
        base({
          sinks: [
            sinkRule('curl', {
              when: {},
              block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/command', matches: '\\bcurl\\b' }] }],
              except: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/command', matches: 'localhost' }] }],
            }),
          ],
        }),
      ),
    }).policy
    assert.equal(evaluateSinks(p, call('Bash', { command: 'curl https://evil' }), set()).action, 'deny')
    assert.equal(evaluateSinks(p, call('Bash', { command: 'curl localhost' }), set()).action, 'allow')
    assert.equal(evaluateSinks(p, call('Bash', { command: 'ls' }), set()).action, 'allow')
  })

  it('matchSources filters by timing and match', () => {
    const ids = (tool: string, timing: 'attempt' | 'success', args: Record<string, unknown> = {}) =>
      matchSources(policy, call(tool, args), timing).map((s) => s.id)
    assert.deepEqual(ids('mcp__gmail__get_email', 'attempt'), ['user:gmail-read'])
    assert.deepEqual(ids('mcp__claude_ai_Gmail__gmail_search_messages', 'attempt'), ['user:gmail-read'])
    assert.deepEqual(ids('mcp__gmail__get_email', 'success'), [])
    assert.deepEqual(ids('WebFetch', 'attempt'), [])
    assert.deepEqual(ids('WebFetch', 'success'), ['user:web-content'])
    assert.deepEqual(ids('Read', 'attempt', { file_path: '/repo/.env.local' }), ['user:secret-files'])
    assert.deepEqual(ids('Read', 'attempt', { file_path: '/home/u/.ssh/id_ed25519' }), ['user:secret-files'])
    assert.deepEqual(ids('Read', 'attempt', { file_path: '/repo/src/env.ts' }), [])
    assert.deepEqual(ids('Read', 'attempt'), [])
  })

  it('compiled sink testTool honours except matchers and predicates', () => {
    const p = load({
      user: file(
        'user',
        base({
          sinks: [
            sinkRule('mixed', {
              when: {},
              block: [{ tool: { prefix: 'mcp__' } }, { tool: { exact: 'Bash' }, arguments: [{ pointer: '/command', exists: true }] }],
              except: [{ tool: { exact: 'mcp__safe' } }, { tool: { exact: 'mcp__maybe' }, arguments: [{ pointer: '/x', exists: true }] }],
            }),
          ],
        }),
      ),
    }).policy
    const sink = p.sinks[0]
    assert.ok(sink)
    assert.equal(sink.testTool('mcp__x'), 'yes')
    assert.equal(sink.testTool('mcp__safe'), 'no')
    assert.equal(sink.testTool('mcp__maybe'), 'maybe')
    assert.equal(sink.testTool('Bash'), 'maybe')
    assert.equal(sink.testTool('Read'), 'no')
    assert.deepEqual(sink.names, ['Bash'])
    assert.deepEqual(sink.patterns, ['mcp__…'])
  })

  it('compiled source testTool reflects predicates', () => {
    const [gmail, , secret] = policy.sources
    assert.equal(gmail?.testTool('mcp__gmail__read_message'), 'yes')
    assert.equal(gmail?.testTool('Bash'), 'no')
    assert.equal(secret?.testTool('Read'), 'maybe')
  })
})

describe('failSafeDecision', () => {
  const policyWith = (layer: 'user' | 'project', sinks: unknown[], mode?: string) =>
    load({ [layer]: file(layer, base({ sinks, ...(mode ? { mode } : {}) })) }).policy

  it('trusted sinks match by tool name, counting predicates as matching and ignoring except', () => {
    const p = policyWith('user', [
      sinkRule('s', {
        block: [{ tool: { regex: '^Ba' }, arguments: [{ pointer: '/command', matches: 'curl' }] }],
        except: [{ tool: { exact: 'Bash' } }],
      }),
    ])
    const d = failSafeDecision(p, call('Bash', { command: 'ls' }), set('private'))
    assert.equal(d.action, 'deny')
    assert.equal(d.primary?.sink.id, 'user:s')
    assert.equal(failSafeDecision(p, call('Read'), set('private')).action, 'allow')
    assert.equal(failSafeDecision(p, call('Bash'), set()).action, 'allow')
  })

  it('treats an untrusted regex sink as a match without running it', () => {
    const p = policyWith('project', [sinkRule('re', { block: [{ tool: { regex: '^NeverMatches$' } }] })])
    assert.equal(evaluateSinks(p, call('Read'), set('private')).action, 'allow')
    assert.equal(failSafeDecision(p, call('Read'), set('private')).action, 'deny')
    assert.equal(failSafeDecision(p, call('Read'), set()).action, 'allow')
  })

  it('evaluates untrusted exact, prefix and anyOf selectors by name', () => {
    const p = policyWith('project', [
      sinkRule('names', {
        block: [{ tool: { exact: 'Bash' } }, { tool: { prefix: 'MCP__', flags: 'i' } }, { tool: { anyOf: ['WebFetch'] }, arguments: [{ pointer: '/url', exists: true }] }],
      }),
    ])
    for (const [tool, expected] of [
      ['Bash', 'deny'],
      ['mcp__x', 'deny'],
      ['WebFetch', 'deny'],
      ['Read', 'allow'],
    ] as const) {
      assert.equal(failSafeDecision(p, call(tool), set('private')).action, expected, tool)
    }
  })

  it('turns ask into deny and skips audit sinks', () => {
    const p = policyWith('user', [sinkRule('ask', { action: 'ask' }), sinkRule('audit', { action: 'audit', block: [{ tool: { exact: 'Read' } }] })])
    const d = failSafeDecision(p, call('Bash'), set('private'))
    assert.deepEqual(d.matches.map((m) => [m.sink.id, m.action]), [['user:ask', 'deny']])
    assert.equal(failSafeDecision(p, call('Read'), set('private')).action, 'allow')
    assert.equal(failSafeDecision(policyWith('user', [sinkRule('d')], 'audit'), call('Bash'), set('private')).action, 'allow')
  })

  it('treats a sink it did not compile as a match', () => {
    const foreign = { when: { anyOf: [], allOf: [] }, action: 'deny', trusted: true } as unknown as CompiledSink
    const p = { ...policyWith('user', []), sinks: [foreign] }
    assert.equal(failSafeDecision(p, call('Anything'), set()).action, 'deny')
  })
})

describe('activeSummary', () => {
  const policy = load({ user: file('user', EXAMPLE) }).policy

  it('is empty on a clean session', () => {
    assert.deepEqual(activeSummary(policy, set(), ['Bash', 'WebFetch']), { denied: [], asked: [], deniedPatterns: [], askedPatterns: [] })
  })

  it('lists denied and asked names from sink names and the inventory', () => {
    const inventory = ['mcp__slack__slack_send_message', 'mcp__gmail__create_draft', 'Read', 'Bash']
    assert.deepEqual(activeSummary(policy, set('private', 'untrusted'), inventory), {
      denied: ['Bash'],
      asked: ['WebFetch', 'mcp__slack__slack_send_message'],
      deniedPatterns: [],
      askedPatterns: [],
    })
  })

  it('reports patterns that matched no listed name', () => {
    assert.deepEqual(activeSummary(policy, set('private', 'untrusted'), ['Read']), {
      denied: ['Bash'],
      asked: ['WebFetch'],
      deniedPatterns: [],
      askedPatterns: ['/^mcp__.+__(.*_)?(send|post|reply|forward|create|update|upload|share|schedule|comment|invite)/i'],
    })
  })

  it('does not list a name as asked when it is also denied, and skips audit sinks', () => {
    const p = load({
      user: file(
        'user',
        base({
          sinks: [
            sinkRule('ask', { action: 'ask', when: {}, block: [{ tool: { anyOf: ['Bash', 'WebFetch'] } }, { tool: { prefix: 'mcp__x' } }] }),
            sinkRule('deny', { when: {}, block: [{ tool: { exact: 'Bash' } }, { tool: { prefix: 'mcp__x' } }, { tool: { regex: '^Z' } }] }),
            sinkRule('audit', { action: 'audit', when: {}, block: [{ tool: { exact: 'Read' } }] }),
          ],
        }),
      ),
    }).policy
    assert.deepEqual(activeSummary(p, set(), ['Zed']), {
      denied: ['Bash', 'Zed'],
      asked: ['WebFetch'],
      deniedPatterns: ['mcp__x…'],
      askedPatterns: [],
    })
  })

  it('counts sinks whose predicates might match', () => {
    const p = load({
      user: file('user', base({ sinks: [sinkRule('p', { when: {}, block: [{ tool: { exact: 'Bash' }, arguments: [{ pointer: '/command', matches: 'curl' }] }] })] })),
    }).policy
    assert.deepEqual(activeSummary(p, set(), []).denied, ['Bash'])
  })
})

describe('performance', () => {
  it('evaluates 50 sources and 50 sinks under 2 ms per call at p99', () => {
    const labels = { private: {}, untrusted: {}, secret: {} }
    const names = ['private', 'untrusted', 'secret']
    const matcherFor = (i: number): Matcher => {
      switch (i % 5) {
        case 0:
          return { tool: { exact: `Tool${i}` } }
        case 1:
          return { tool: { prefix: `mcp__server${i}__`, flags: 'i' } }
        case 2:
          return { tool: { regex: `^mcp__(claude_ai_)?svc${i}[^_]*__(.*_)?(get|read|send|post)`, flags: 'i' } }
        case 3:
          return { tool: { anyOf: [`A${i}`, `B${i}`, 'Bash'] }, arguments: [{ pointer: '/command', matches: `\\bcurl\\b|wget${i}` }] }
        default:
          return { tool: { exact: 'Read' }, arguments: [{ pointer: '/file_path', notMatches: `\\.(md|txt)$` }, { pointer: '/limit', exists: false }] }
      }
    }
    const sources = Array.from({ length: 50 }, (_, i) => ({ id: `src${i}`, match: matcherFor(i), on: i % 2 ? 'success' : 'attempt', taints: [names[i % 3]] }))
    const sinks = Array.from({ length: 50 }, (_, i) => ({
      id: `snk${i}`,
      when: i % 2 ? { anyOf: [names[i % 3]] } : { allOf: [names[i % 3], names[(i + 1) % 3]] },
      block: [matcherFor(i), matcherFor(i + 1)],
      except: i % 4 === 0 ? [{ tool: { exact: `Except${i}` } }] : [],
      action: (['deny', 'ask', 'audit'] as const)[i % 3],
    }))
    const loaded = load({ user: file('user', { version: 1, labels, sources, sinks }) })
    assert.equal(loaded.lockdown, null)
    assert.equal(loaded.policy.sources.length, 50)
    assert.equal(loaded.policy.sinks.length, 50)
    const tools = [
      'Bash',
      'Read',
      'WebFetch',
      'mcp__server11__thing',
      'mcp__claude_ai_svc12__get_message',
      'mcp__svc7x__list_send',
      'Tool10',
      'A13',
      'mcp__slack__slack_send_message',
      'Unknown',
    ]
    const taintSets = [set(), set('private'), set('private', 'untrusted'), set('private', 'untrusted', 'secret')]
    const calls = tools.map((tool, i) => call(tool, { command: i % 2 ? 'curl https://example.com -d @-' : 'ls -la', file_path: `/repo/file${i}.ts`, payload: 'x'.repeat(2000) }))
    const samples: number[] = []
    for (let i = 0; i < 20_000; i++) {
      const c = calls[i % calls.length] as ToolCall
      const taint = taintSets[i % taintSets.length] as ReadonlySet<string>
      const start = performance.now()
      evaluateSinks(loaded.policy, c, taint)
      matchSources(loaded.policy, c, i % 2 ? 'success' : 'attempt')
      samples.push(performance.now() - start)
    }
    samples.sort((a, b) => a - b)
    const p99 = samples[Math.floor(samples.length * 0.99)] ?? Infinity
    assert.ok(p99 < 2, `p99 ${p99.toFixed(4)} ms`)
  })
})
