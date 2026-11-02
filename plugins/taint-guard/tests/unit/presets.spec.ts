import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  FAMILY_TOKENS,
  PRESETS,
  READ_VERBS,
  SCHEMA_ID,
  WRITE_VERBS,
  classifyTool,
  type ToolClass,
} from '../../src/presets.ts'
import type { Matcher, PolicyFile, RuleRef, SinkRule, SourceRule, ToolSelector } from '../../src/types.ts'
import { renderPresets } from '../../scripts/presets.ts'

const ROOT = join(import.meta.dirname, '..', '..')

const isRef = (rule: SourceRule | SinkRule | RuleRef): rule is RuleRef => !('match' in rule) && !('block' in rule)

function preset(name: 'strict' | 'trifecta'): PolicyFile {
  const policy = PRESETS[name]
  assert.ok(policy)
  return policy
}

function sources(policy: PolicyFile): SourceRule[] {
  return (policy.sources ?? []).filter((rule): rule is SourceRule => !isRef(rule))
}

function sinks(policy: PolicyFile): SinkRule[] {
  return (policy.sinks ?? []).filter((rule): rule is SinkRule => !isRef(rule))
}

function source(policy: PolicyFile, id: string): SourceRule {
  const rule = sources(policy).find((candidate) => candidate.id === id)
  assert.ok(rule, id)
  return rule
}

function sink(policy: PolicyFile, id: string): SinkRule {
  const rule = sinks(policy).find((candidate) => candidate.id === id)
  assert.ok(rule, id)
  return rule
}

function regexOf(matcher: Matcher): RegExp {
  assert.ok('regex' in matcher.tool, JSON.stringify(matcher.tool))
  return new RegExp(matcher.tool.regex, matcher.tool.flags ?? '')
}

function selects(selector: ToolSelector, tool: string): boolean {
  if ('exact' in selector) return selector.exact === tool
  if ('anyOf' in selector) return selector.anyOf.includes(tool)
  if ('prefix' in selector) {
    return selector.flags === 'i'
      ? tool.toLowerCase().startsWith(selector.prefix.toLowerCase())
      : tool.startsWith(selector.prefix)
  }
  return new RegExp(selector.regex, selector.flags ?? '').test(tool)
}

const toolOnly = (matcher: Matcher, tool: string): boolean =>
  (matcher.arguments ?? []).length === 0 && selects(matcher.tool, tool)

const firingSources = (policy: PolicyFile, tool: string): string[] =>
  sources(policy)
    .filter((rule) => toolOnly(rule.match, tool))
    .map((rule) => rule.id)

const matchingSinks = (policy: PolicyFile, tool: string): string[] =>
  sinks(policy)
    .filter((rule) => rule.block.some((m) => toolOnly(m, tool)) && !(rule.except ?? []).some((m) => selects(m.tool, tool)))
    .map((rule) => rule.id)

const CORPUS: readonly string[] = [
  'mcp__claude_ai_Gmail__gmail_search_messages',
  'mcp__claude_ai_Gmail__gmail_read_message',
  'mcp__claude_ai_Gmail__gmail_create_draft',
  'mcp__claude_ai_Gmail__gmail_list_labels',
  'mcp__claude_ai_Gmail__authenticate',
  'mcp__claude_ai_Gmail__complete_authentication',
  'mcp__claude_ai_Google_Drive__search',
  'mcp__claude_ai_Google_Drive__fetch',
  'mcp__claude_ai_Google_Drive__authenticate',
  'mcp__claude_ai_Google_Calendar__list_events',
  'mcp__claude_ai_Google_Calendar__create_event',
  'mcp__claude_ai_Claude_Docs__create',
  'mcp__claude_ai_Claude_Docs__read',
  'mcp__claude_ai_Claude_Docs__batch',
  'mcp__claude_ai_Slack__slack_send_message',
  'mcp__claude_ai_Slack__slack_search_public',
  'mcp__gmail__read_message',
  'mcp__gmail__apply_label',
  'mcp__gmail__archive',
  'mcp__gmail__send_email',
  'mcp__gmail__create_draft',
  'mcp__gmail__drafts_create_draft',
  'mcp__gmail__create_draft_and_send',
  'mcp__mail__list_messages',
  'mcp__Outlook__ListMessages',
  'mcp__outlook__reply_all',
  'mcp__google-mail__getThread',
  'mcp__googlemail__download-attachment',
  'mcp__slack__slack_send_message',
  'mcp__slack__slack_search_public',
  'mcp__slack__conversations_history',
  'mcp__slack__add_reaction',
  'mcp__teams__post_message',
  'mcp__notion__notion-search',
  'mcp__notion__notion-update-page',
  'mcp__notion__move_pages',
  'mcp__gdrive__upload_file',
  'mcp__onedrive__share_link',
  'mcp__SharePoint__GetFile',
  'mcp__github__create_issue',
  'mcp__github__get_issue',
  'mcp__github__search_code',
  'mcp__linear__update_issue',
  'mcp__jira__comment_on_issue',
  'mcp__context7__query-docs',
  'mcp__context7__resolve-library-id',
  'mcp__sentry__authenticate',
  'mcp__plugin_oh-my-claudecode_t__ast_grep_search',
  'mcp__plugin_oh-my-claudecode_t__notepad_write_manual',
  'mcp__claude-in-chrome__tabs_create_mcp',
  'mcp__claude-in-chrome__get_page_text',
  'mcp__chatbot__send',
  'mcp__x__getter',
  'mcp__x__forgetful',
  'mcp__x___send',
  'mcp__x-mail__send',
  'mcp__mail___archive',
  'mcp____send',
  'mcp__gmail',
  'mcp__gmail_',
  'MCP__Gmail__Read_Message',
  'mcp__GMAIL__SEARCH',
  'Bash',
  'WebFetch',
  'WebSearch',
  'Read',
  'Grep',
  'Write',
  'Edit',
  'NotebookEdit',
  'mcp_gmail__read',
  'gmail__read_message',
  '',
]

function draftByName(tool: string, cls: ToolClass): boolean {
  if (cls.family !== 'mail' || cls.server === null) return false
  const segment = tool.slice(5 + cls.server.length + 2).toLowerCase()
  return segment === 'create_draft' || segment.endsWith('_create_draft') || segment.endsWith('-create_draft')
}

function checkAgreement(tool: string): void {
  const policy = preset('trifecta')
  const cls = classifyTool(tool)
  const read = cls.verb === 'read' || cls.verb === 'both'
  const write = cls.verb === 'write' || cls.verb === 'both'
  const outbound = sink(policy, 'outbound-private').block
  const writeMatcher = outbound.find((m) => 'regex' in m.tool && !m.tool.regex.includes('(?=')) as Matcher
  const label = `${JSON.stringify(tool)} ${JSON.stringify(cls)}`
  assert.equal(regexOf(source(policy, 'private-read').match).test(tool), cls.family !== null && read, `private-read ${label}`)
  assert.equal(regexOf(source(policy, 'private-other').match).test(tool), cls.family !== null && cls.verb === 'other', `private-other ${label}`)
  assert.equal(regexOf(writeMatcher).test(tool), cls.mcp && write, `mcp-write ${label}`)
  const except = sink(policy, 'outbound-private').except ?? []
  assert.equal(except.length, 1)
  assert.equal(regexOf(except[0] as Matcher).test(tool), draftByName(tool, cls), `create_draft ${label}`)
}

function mulberry32(seed: number): () => number {
  let state = seed
  return () => {
    state = (state + 0x6d2b79f5) | 0
    let t = Math.imul(state ^ (state >>> 15), 1 | state)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

describe('classifyTool', () => {
  const cases: Array<[string, ToolClass]> = [
    ['mcp__claude_ai_Gmail__gmail_search_messages', { mcp: true, server: 'claude_ai_Gmail', family: 'mail', verb: 'read' }],
    ['mcp__claude_ai_Google_Drive__search', { mcp: true, server: 'claude_ai_Google_Drive', family: 'docs', verb: 'read' }],
    ['mcp__claude_ai_Gmail__gmail_create_draft', { mcp: true, server: 'claude_ai_Gmail', family: 'mail', verb: 'write' }],
    ['mcp__claude_ai_Google_Calendar__list_events', { mcp: true, server: 'claude_ai_Google_Calendar', family: null, verb: 'read' }],
    ['mcp__mail__list_messages', { mcp: true, server: 'mail', family: 'mail', verb: 'read' }],
    ['mcp__gmail__apply_label', { mcp: true, server: 'gmail', family: 'mail', verb: 'other' }],
    ['mcp__slack__slack_send_message', { mcp: true, server: 'slack', family: 'chat', verb: 'write' }],
    ['mcp__slack__conversations_history', { mcp: true, server: 'slack', family: 'chat', verb: 'read' }],
    ['mcp__notion__notion-search', { mcp: true, server: 'notion', family: 'docs', verb: 'read' }],
    ['mcp__Outlook__ListMessages', { mcp: true, server: 'Outlook', family: 'mail', verb: 'read' }],
    ['mcp__SharePoint__GetFile', { mcp: true, server: 'SharePoint', family: 'docs', verb: 'read' }],
    ['MCP__Gmail__Read_Message', { mcp: true, server: 'Gmail', family: 'mail', verb: 'read' }],
    ['mcp__gmail__create_draft_and_send', { mcp: true, server: 'gmail', family: 'mail', verb: 'write' }],
    ['mcp__gmail__read_and_reply', { mcp: true, server: 'gmail', family: 'mail', verb: 'both' }],
    ['mcp__github__create_issue', { mcp: true, server: 'github', family: null, verb: 'write' }],
    ['mcp__context7__query-docs', { mcp: true, server: 'context7', family: null, verb: 'other' }],
    ['mcp__claude-in-chrome__get_page_text', { mcp: true, server: 'claude-in-chrome', family: null, verb: 'read' }],
    ['mcp__x__forgetful', { mcp: true, server: 'x', family: null, verb: 'other' }],
    ['mcp__x___send', { mcp: true, server: 'x', family: null, verb: 'write' }],
    ['mcp____send', { mcp: true, server: '', family: null, verb: 'write' }],
    ['mcp__gmail', { mcp: false, server: null, family: null, verb: null }],
    ['mcp_gmail__read', { mcp: false, server: null, family: null, verb: null }],
    ['Bash', { mcp: false, server: null, family: null, verb: null }],
    ['WebFetch', { mcp: false, server: null, family: null, verb: null }],
    ['Read', { mcp: false, server: null, family: null, verb: null }],
  ]
  for (const [tool, expected] of cases) {
    it(`classifies ${tool}`, () => assert.deepEqual(classifyTool(tool), expected))
  }

  it('prefers the first family in mail, docs, chat order', () => {
    assert.equal(classifyTool('mcp__slack_gmail_bridge__send').family, 'mail')
    assert.equal(classifyTool('mcp__teams_drive__list').family, 'docs')
  })

  it('lists the documented tokens and verbs', () => {
    assert.deepEqual([...FAMILY_TOKENS.mail], ['gmail', 'google_mail', 'google-mail', 'googlemail', 'outlook', 'mail'])
    assert.ok(FAMILY_TOKENS.docs.includes('sharepoint') && FAMILY_TOKENS.chat.includes('teams'))
    assert.deepEqual([...READ_VERBS], ['get', 'read', 'search', 'list', 'fetch', 'download', 'history'])
    assert.equal(WRITE_VERBS.length, 11)
  })
})

describe('preset regexes agree with classifyTool', () => {
  it('has a corpus of at least 40 names', () => assert.ok(CORPUS.length >= 40))

  for (const tool of CORPUS) {
    it(`agrees on ${JSON.stringify(tool)}`, () => checkAgreement(tool))
  }

  it('agrees on 5,000 generated names', () => {
    const random = mulberry32(42)
    const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T
    const parts = [
      ...Object.values(FAMILY_TOKENS).flat(),
      ...READ_VERBS,
      ...WRITE_VERBS,
      'create_draft',
      'claude_ai_',
      'Gmail',
      'DRIVE',
      'x',
      'Q',
      'label',
      '_',
      '__',
      '___',
      '-',
      'mcp__',
      '\n',
    ]
    for (let n = 0; n < 5000; n++) {
      const pieces = Array.from({ length: 1 + Math.floor(random() * 6) }, () => pick(parts))
      checkAgreement(`${random() < 0.9 ? 'mcp__' : ''}${pieces.join('')}`)
    }
  })

  it('shares the source and sink regexes between both presets', () => {
    assert.deepEqual(preset('strict').sources, preset('trifecta').sources)
    assert.deepEqual(preset('strict').labels, preset('trifecta').labels)
  })
})

describe('spec acceptance at the regex level', () => {
  it('18: the trifecta classifies Gmail and mail reads as sources and a Slack send as a sink', () => {
    const trifecta = preset('trifecta')
    assert.deepEqual(firingSources(trifecta, 'mcp__claude_ai_Gmail__gmail_search_messages'), ['private-read'])
    assert.deepEqual(firingSources(trifecta, 'mcp__mail__list_messages'), ['private-read'])
    assert.deepEqual(firingSources(trifecta, 'mcp__slack__slack_send_message'), [])
    assert.deepEqual(matchingSinks(trifecta, 'mcp__slack__slack_send_message'), ['outbound-secret', 'outbound-private'])
  })

  it('19: an unknown-verb tool on a mail server is both source and sink', () => {
    for (const name of ['strict', 'trifecta'] as const) {
      const policy = preset(name)
      assert.deepEqual(firingSources(policy, 'mcp__gmail__apply_label'), ['private-other'])
      assert.ok(matchingSinks(policy, 'mcp__gmail__apply_label').length > 0, name)
    }
  })

  it('exempts a Gmail create_draft only from the private sink', () => {
    const trifecta = preset('trifecta')
    assert.deepEqual(matchingSinks(trifecta, 'mcp__claude_ai_Gmail__gmail_create_draft'), ['outbound-secret'])
    assert.deepEqual(matchingSinks(trifecta, 'mcp__slack__create_draft'), ['outbound-secret', 'outbound-private'])
    assert.deepEqual(matchingSinks(preset('strict'), 'mcp__claude_ai_Gmail__gmail_create_draft'), ['outbound-any'])
  })

  it('blocks Bash and WebFetch as outbound and taints on web content', () => {
    for (const tool of ['Bash', 'WebFetch']) {
      assert.deepEqual(matchingSinks(preset('trifecta'), tool), ['outbound-secret', 'outbound-private'])
    }
    assert.deepEqual(firingSources(preset('trifecta'), 'WebSearch'), ['web-content'])
    assert.deepEqual(matchingSinks(preset('trifecta'), 'WebSearch'), [])
    assert.deepEqual(matchingSinks(preset('trifecta'), 'Write'), [])
  })

  it('strict blocks WebSearch and file writes once any label is present', () => {
    const strict = preset('strict')
    for (const tool of ['WebSearch', 'Write', 'Edit', 'NotebookEdit', 'Bash', 'mcp__github__create_issue']) {
      assert.deepEqual(matchingSinks(strict, tool), ['outbound-any'], tool)
    }
    assert.deepEqual(sink(strict, 'outbound-any').when, { anyOf: ['private', 'untrusted', 'secret'] })
    assert.deepEqual(matchingSinks(strict, 'Read'), [])
  })

  it('declares the documented labels and actions and leaves the global settings to the policy files', () => {
    for (const name of ['strict', 'trifecta'] as const) {
      const policy = preset(name)
      assert.equal(policy.version, 1)
      for (const key of ['mode', 'userDeclassify', 'onUnknownHistory', 'resetOnClear', 'subagents'] as const) {
        assert.equal(policy[key], undefined, `${name} leaves ${key} unset`)
      }
      assert.deepEqual(Object.keys(policy.labels), ['private', 'untrusted', 'secret'])
      assert.deepEqual(
        sources(policy).map((rule) => [rule.id, rule.on, rule.taints]),
        [
          ['private-read', 'attempt', ['private', 'untrusted']],
          ['private-other', 'attempt', ['private', 'untrusted']],
          ['web-content', 'success', ['untrusted']],
          ['secret-files', 'attempt', ['secret']],
          ['secret-grep', 'attempt', ['secret']],
        ],
      )
    }
    const trifecta = preset('trifecta')
    assert.equal(sink(trifecta, 'outbound-secret').action, 'deny')
    assert.deepEqual(sink(trifecta, 'outbound-secret').when, { anyOf: ['secret'] })
    assert.equal(sink(trifecta, 'outbound-private').action, 'ask')
    assert.deepEqual(sink(trifecta, 'outbound-private').when, { allOf: ['private', 'untrusted'] })
    assert.equal(PRESETS.none, null)
  })
})

describe('secret-file regex', () => {
  const policy = preset('trifecta')
  const predicates = ['secret-files', 'secret-grep'].map((id) => {
    const rule = source(policy, id)
    const predicate = rule.match.arguments?.[0]
    assert.ok(predicate && 'matches' in predicate)
    return { tool: rule.match.tool, pointer: predicate.pointer, regex: new RegExp(predicate.matches, predicate.flags ?? '') }
  })

  it('reads /file_path for Read and /path for Grep', () => {
    assert.deepEqual(
      predicates.map(({ tool, pointer }) => [tool, pointer]),
      [
        [{ exact: 'Read' }, '/file_path'],
        [{ exact: 'Grep' }, '/path'],
      ],
    )
  })

  const secret = [
    '.env',
    '/repo/.env',
    '/repo/.env.local',
    '/repo/.env.production',
    'C:\\repo\\.env',
    '/repo/.ENV',
    '/home/u/.ssh/id_ed25519',
    '~/.ssh/id_rsa',
    '/home/u/.ssh/id_ecdsa',
    '/home/u/.ssh/id_dsa',
    '~/.aws/credentials',
    '/home/u/.netrc',
    '/home/u/.pgpass',
    '/repo/.npmrc',
    '/etc/ssl/cert.pem',
    '/etc/ssl/server.KEY',
  ]
  const ordinary = [
    '/repo/.env.example',
    '/repo/.env.sample',
    '/repo/.env.template',
    '/repo/.env.dist',
    '/home/u/.ssh/id_ed25519.pub',
    '/home/u/.ssh/known_hosts',
    '/repo/credentials.json',
    '/repo/src/credentials.ts',
    '/repo/my.env',
    '/repo/environment.ts',
    '/repo/.env/readme.md',
    '/repo/keys.ts',
    '/repo/src/index.ts',
    '',
  ]
  for (const path of secret) {
    it(`matches ${path}`, () => predicates.forEach(({ regex }) => assert.equal(regex.test(path), true)))
  }
  for (const path of ordinary) {
    it(`does not match ${JSON.stringify(path)}`, () => predicates.forEach(({ regex }) => assert.equal(regex.test(path), false)))
  }
})

describe('preset files', () => {
  it('equal the generator output', () => {
    const rendered = renderPresets()
    assert.deepEqual(Object.keys(rendered).sort(), ['strict.json', 'trifecta.json'])
    for (const [file, text] of Object.entries(rendered)) {
      assert.equal(readFileSync(join(ROOT, 'presets', file), 'utf8'), text, file)
      assert.deepEqual(JSON.parse(text), { $schema: SCHEMA_ID, ...PRESETS[file.replace('.json', '') as 'strict'] })
    }
  })

  it('pass the generator --check', () => {
    const output = execFileSync(process.execPath, [join(ROOT, 'scripts', 'presets.ts'), '--check'], {
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'pipe'],
    })
    assert.equal(output, '')
  })
})

describe('preset regex safety', () => {
  const patterns: Array<{ where: string; source: string; flags: string }> = []
  const collect = (where: string, matcher: Matcher): void => {
    if ('regex' in matcher.tool) patterns.push({ where, source: matcher.tool.regex, flags: matcher.tool.flags ?? '' })
    for (const predicate of matcher.arguments ?? []) {
      if ('matches' in predicate) patterns.push({ where, source: predicate.matches, flags: predicate.flags ?? '' })
      if ('notMatches' in predicate) patterns.push({ where, source: predicate.notMatches, flags: predicate.flags ?? '' })
    }
  }
  for (const name of ['strict', 'trifecta'] as const) {
    const policy = preset(name)
    for (const rule of sources(policy)) collect(`${name}:${rule.id}`, rule.match)
    for (const rule of sinks(policy)) {
      for (const matcher of [...rule.block, ...(rule.except ?? [])]) collect(`${name}:${rule.id}`, matcher)
    }
  }

  const adversarial = [
    `mcp__${'mail'.repeat(2500)}`,
    `mcp__${'mail'.repeat(2500)}__x`,
    `mcp__${'mail'.repeat(1250)}__${'mail'.repeat(1250)}`,
    `mcp__${'gmai'.repeat(2500)}__x`,
    `mcp__${'_a'.repeat(5000)}`,
    `mcp__${'a_'.repeat(5000)}__`,
    `mcp__${'mail_'.repeat(2000)}__${'_x'.repeat(2500)}`,
    `mcp__gmail__${'_'.repeat(10000)}`,
    `mcp__gmail__${'-ge'.repeat(3333)}`,
    `mcp__gmail__${'_create_draf'.repeat(833)}`,
    `mcp__gmail__${'create_draft_'.repeat(769)}x`,
    `mcp__${'slack'.repeat(1000)}__${'_sen'.repeat(1250)}`,
    `${'mcp__'.repeat(2000)}`,
    `mcp__${'__'.repeat(5000)}`,
    'a'.repeat(10000),
    '/'.repeat(10000),
    '\\'.repeat(10000),
    `/${'.env'.repeat(2500)}/`,
    `${'/.env'.repeat(2000)}.example/`,
    `${'x.pe'.repeat(2500)}/`,
    `/${'id_'.repeat(3333)}`,
    `${'/a'.repeat(5000)}.pem.x`,
  ]

  it('collects every preset regex', () => assert.ok(patterns.length >= 12, `${patterns.length}`))

  for (const { where, source, flags } of patterns) {
    it(`${where} /${source.slice(0, 40)}…/ compiles and stays under 50 ms on adversarial names`, () => {
      const regex = new RegExp(source, flags)
      new RegExp(source, `${flags}u`)
      for (const input of adversarial) {
        assert.ok(input.length >= 9990, `${input.length}`)
        const started = performance.now()
        regex.test(input)
        const elapsed = performance.now() - started
        assert.ok(elapsed < 50, `${elapsed.toFixed(1)} ms on ${input.slice(0, 30)}…`)
      }
    })
  }
})

describe('describePattern', () => {
  it('names the preset patterns in plain words and leaves others alone', async () => {
    const { describePattern, MCP_WRITE_REGEX, PRIVATE_OTHER_REGEX } = await import('../../src/presets.ts')
    assert.equal(
      describePattern(`/${MCP_WRITE_REGEX}/i`),
      'MCP tools that send, post, reply, forward, create, update, upload, share, schedule, comment or invite',
    )
    assert.equal(describePattern(`/${PRIVATE_OTHER_REGEX}/i`), 'other tools on mail, documents or chat MCP servers')
    assert.equal(describePattern('/^mcp__x__/'), '/^mcp__x__/')
  })
})
