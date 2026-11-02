import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  EMPTY_TAINT,
  OWN_DENIAL_PREFIX,
  RECORD_PREFIX,
  addFiring,
  compactInstructions,
  countBlocked,
  findRecords,
  formatRecord,
  isOwnDenial,
  lastToolUseId,
  parseStored,
  rebuild,
  removeLabels,
  sameLabels,
  staleStoreKeys,
  storeKey,
  toStored,
} from '../../src/state.ts'
import type { RebuildInput } from '../../src/state.ts'
import type { Firing, MessageLike, TaintSnapshot, Timing, ToolCall } from '../../src/types.ts'

const fire = (rule: string, labels: string[], extra: Partial<Firing> = {}): Firing => ({
  rule,
  tool: 'mcp__gmail__read_message',
  labels,
  at: 1000,
  ...extra,
})

type Use = MessageLike['toolUses'][number]

const use = (tool: string, input: Record<string, unknown>, extra: Partial<Use> = {}): Use => ({
  tool_use_id: `toolu_${tool}_${Math.random().toString(36).slice(2, 8)}`,
  tool,
  input,
  ...extra,
})

const assistant = (toolUses: Use[], text = ''): MessageLike => ({ role: 'assistant', text, toolUses })
const user = (text: string, toolResults?: MessageLike['toolResults']): MessageLike =>
  toolResults ? { role: 'user', text, toolUses: [], toolResults } : { role: 'user', text, toolUses: [] }

const MAIL = 'mcp__gmail__read_message'
const FETCH = 'WebFetch'
const DECLARED = ['private', 'secret', 'untrusted']

function matcher(call: ToolCall, timing: Timing): Array<{ id: string; taints: string[] }> {
  const out: Array<{ id: string; taints: string[] }> = []
  if (timing === 'attempt' && call.tool === MAIL) out.push({ id: 'user:gmail-read', taints: ['private', 'untrusted'] })
  if (timing === 'success' && call.tool === FETCH) out.push({ id: 'preset:web-content', taints: ['untrusted'] })
  if (timing === 'attempt' && call.tool === 'Read' && /\.env$/.test(String(call.args.file_path))) {
    out.push({ id: 'user:secrets', taints: ['secret'] })
  }
  return out
}

const input = (overrides: Partial<RebuildInput>): RebuildInput => ({
  messages: [],
  match: matcher,
  declaredLabels: DECLARED,
  onUnknownHistory: 'assume-tainted',
  storeCopy: null,
  historyLimit: 4096,
  at: 5000,
  ...overrides,
})

describe('EMPTY_TAINT', () => {
  it('is empty and cannot be mutated', () => {
    assert.deepEqual(EMPTY_TAINT, { labels: [], firedBy: [], blockedCount: 0 })
    assert.throws(() => (EMPTY_TAINT.labels as string[]).push('x'))
  })
})

describe('addFiring', () => {
  it('adds labels sorted and unique, recording the firing', () => {
    const { next, added } = addFiring(EMPTY_TAINT, fire('user:gmail-read', ['untrusted', 'private', 'private']))
    assert.deepEqual(next.labels, ['private', 'untrusted'])
    assert.deepEqual(added, ['private', 'untrusted'])
    assert.equal(next.firedBy.length, 1)
    assert.deepEqual(next.firedBy[0], fire('user:gmail-read', ['private', 'untrusted']))
  })

  it('lists only the labels the firing added', () => {
    const first = addFiring(EMPTY_TAINT, fire('a', ['private'])).next
    const { next, added } = addFiring(first, fire('b', ['private', 'secret'], { agentId: 'ag1', toolUseId: 't1' }))
    assert.deepEqual(added, ['secret'])
    assert.deepEqual(next.labels, ['private', 'secret'])
    assert.deepEqual(next.firedBy[1], { rule: 'b', tool: MAIL, labels: ['secret'], at: 1000, agentId: 'ag1', toolUseId: 't1' })
  })

  it('records nothing when no label is new', () => {
    const first = addFiring(EMPTY_TAINT, fire('a', ['private'])).next
    const { next, added } = addFiring(first, fire('b', ['private']))
    assert.deepEqual(added, [])
    assert.equal(next.firedBy.length, 1)
    assert.deepEqual(next.labels, ['private'])
  })

  it('never mutates its input', () => {
    const before: TaintSnapshot = { labels: ['private'], firedBy: [fire('a', ['private'])], blockedCount: 2 }
    const frozen = structuredClone(before)
    const f = fire('b', ['secret'])
    const { next } = addFiring(before, f)
    assert.deepEqual(before, frozen)
    assert.deepEqual(f.labels, ['secret'])
    assert.equal(next.blockedCount, 2)
    assert.notEqual(next.firedBy, before.firedBy)
  })

  it('caps firedBy at 100, keeping the earliest, while still adding labels', () => {
    let snap: TaintSnapshot = EMPTY_TAINT
    for (let i = 0; i < 105; i++) snap = addFiring(snap, fire(`r${i}`, [`l${i}`])).next
    assert.equal(snap.firedBy.length, 100)
    assert.equal(snap.firedBy[0]?.rule, 'r0')
    assert.equal(snap.firedBy[99]?.rule, 'r99')
    assert.equal(snap.labels.length, 105)
    assert.ok(snap.labels.includes('l104'))
  })
})

describe('removeLabels', () => {
  const snap: TaintSnapshot = {
    labels: ['private', 'secret', 'untrusted'],
    firedBy: [fire('a', ['private', 'untrusted']), fire('b', ['secret'])],
    blockedCount: 3,
  }

  it('removes the named labels and trims firings', () => {
    const { next, removed } = removeLabels(snap, ['untrusted', 'secret', 'absent'])
    assert.deepEqual(removed, ['secret', 'untrusted'])
    assert.deepEqual(next.labels, ['private'])
    assert.deepEqual(next.firedBy, [fire('a', ['private'])])
    assert.equal(next.blockedCount, 3)
    assert.deepEqual(snap.labels, ['private', 'secret', 'untrusted'])
    assert.deepEqual(snap.firedBy[0]?.labels, ['private', 'untrusted'])
  })

  it('removes everything when no labels are given', () => {
    const { next, removed } = removeLabels(snap)
    assert.deepEqual(removed, ['private', 'secret', 'untrusted'])
    assert.deepEqual(next.labels, [])
    assert.deepEqual(next.firedBy, [])
    assert.equal(next.blockedCount, 3)
  })

  it('removes nothing for labels not held', () => {
    const { next, removed } = removeLabels(snap, ['other'])
    assert.deepEqual(removed, [])
    assert.deepEqual(next, snap)
  })
})

describe('countBlocked', () => {
  it('increments blockedCount without mutating', () => {
    const snap: TaintSnapshot = { labels: ['private'], firedBy: [], blockedCount: 1 }
    const next = countBlocked(snap)
    assert.equal(next.blockedCount, 2)
    assert.equal(snap.blockedCount, 1)
    assert.deepEqual(next.labels, ['private'])
  })
})

describe('sameLabels', () => {
  it('compares label sets', () => {
    assert.equal(sameLabels(['a', 'b'], ['b', 'a']), true)
    assert.equal(sameLabels([], []), true)
    assert.equal(sameLabels(['a'], ['a', 'b']), false)
    assert.equal(sameLabels(['a', 'c'], ['a', 'b']), false)
    assert.equal(sameLabels(['a', 'a'], ['a']), true)
  })
})

describe('taint records', () => {
  it('formats a record with sorted labels', () => {
    assert.equal(formatRecord(['untrusted', 'private']), 'TaintGuard taint record v1: labels=private,untrusted')
    assert.equal(formatRecord([]), RECORD_PREFIX)
  })

  it('round-trips through findRecords', () => {
    const line = formatRecord(['secret', 'private', 'untrusted'])
    assert.deepEqual(findRecords(line), [{ labels: ['private', 'secret', 'untrusted'], excerpt: line }])
  })

  it('finds every occurrence, each with its own line', () => {
    const text = `Summary of work.\n  ${formatRecord(['private'])}  \nmore\n\`${formatRecord(['untrusted'])}\`.`
    const found = findRecords(text)
    assert.equal(found.length, 2)
    assert.deepEqual(found[0], { labels: ['private'], excerpt: formatRecord(['private']) })
    assert.deepEqual(found[1]?.labels, ['untrusted'])
    assert.equal(found[1]?.excerpt, `\`${formatRecord(['untrusted'])}\`.`)
  })

  it('keeps only valid label names', () => {
    const tooLong = 'x'.repeat(33)
    const found = findRecords(`${RECORD_PREFIX}private,${tooLong},ok-1, spaced ,under_score`)
    assert.deepEqual(found[0]?.labels, ['ok-1', 'private', 'spaced', 'under'])
  })

  it('stops at the end of the line', () => {
    const found = findRecords(`${RECORD_PREFIX}private\nsecret,untrusted`)
    assert.deepEqual(found[0]?.labels, ['private'])
  })

  it('yields an empty label list for an empty record', () => {
    assert.deepEqual(findRecords(`${RECORD_PREFIX}\n`), [{ labels: [], excerpt: RECORD_PREFIX.trim() }])
  })

  it('caps the excerpt at 120 characters and keeps the record in view', () => {
    const text = 'y'.repeat(300) + ' ' + formatRecord(['private']) + ' ' + 'z'.repeat(300)
    const [record] = findRecords(text)
    assert.ok(record)
    assert.ok(record.excerpt.length <= 120)
    assert.ok(record.excerpt.startsWith(RECORD_PREFIX))
    assert.deepEqual(record.labels, ['private'])
  })

  it('finds nothing in plain text', () => {
    assert.deepEqual(findRecords('TaintGuard taint record v2: labels=private'), [])
    assert.deepEqual(findRecords(''), [])
  })
})

describe('compactInstructions', () => {
  const ask =
    'TaintGuard: this conversation holds tainted content. Copy the following line verbatim, on a line of its own, into the summary:\n' +
    'TaintGuard taint record v1: labels=private,untrusted'

  it('appends the request after existing instructions', () => {
    assert.equal(compactInstructions('Keep it short.', ['untrusted', 'private']), `Keep it short.\n\n${ask}`)
  })

  it('stands alone with no existing instructions', () => {
    assert.equal(compactInstructions(undefined, ['private', 'untrusted']), ask)
    assert.equal(compactInstructions('', ['private', 'untrusted']), ask)
  })

  it('carries a record findRecords reads back', () => {
    assert.deepEqual(findRecords(compactInstructions('x', ['secret']))[0]?.labels, ['secret'])
  })
})

describe('isOwnDenial', () => {
  it('recognises TaintGuard refusals only', () => {
    assert.equal(isOwnDenial(`${OWN_DENIAL_PREFIX}Bash. Bash is disabled`), true)
    assert.equal(isOwnDenial('Error: TaintGuard refused Bash'), false)
    assert.equal(isOwnDenial(undefined), false)
    assert.equal(isOwnDenial(''), false)
  })
})

describe('rebuild', () => {
  it('replays an attempt source (spec test 14)', () => {
    const result = rebuild(input({ messages: [assistant([use(MAIL, { id: 'm1' }, { text: 'Hi' })])] }))
    assert.deepEqual(result.snapshot.labels, ['private', 'untrusted'])
    assert.deepEqual(result.added, ['private', 'untrusted'])
    assert.equal(result.truncated, false)
    assert.deepEqual(result.records, [])
    assert.equal(result.snapshot.firedBy[0]?.rule, 'user:gmail-read')
    assert.equal(result.snapshot.firedBy[0]?.tool, MAIL)
    assert.equal(result.snapshot.firedBy[0]?.at, 5000)
  })

  it('fires attempt sources for errored and in-flight calls', () => {
    const errored = rebuild(input({ messages: [assistant([use(MAIL, {}, { text: 'Permission denied', isError: true })])] }))
    assert.deepEqual(errored.snapshot.labels, ['private', 'untrusted'])
    const inFlight = rebuild(input({ messages: [assistant([use(MAIL, {})])] }))
    assert.deepEqual(inFlight.snapshot.labels, ['private', 'untrusted'])
  })

  it('fires success sources only for answered calls without error', () => {
    const ok = rebuild(input({ messages: [assistant([use(FETCH, { url: 'https://x' }, { text: '<html>' })])] }))
    assert.deepEqual(ok.snapshot.labels, ['untrusted'])
    const failed = rebuild(input({ messages: [assistant([use(FETCH, { url: 'https://x' }, { text: '404', isError: true })])] }))
    assert.deepEqual(failed.snapshot.labels, [])
    const pending = rebuild(input({ messages: [assistant([use(FETCH, { url: 'https://x' })])] }))
    assert.deepEqual(pending.snapshot.labels, [])
  })

  it('skips calls TaintGuard itself refused', () => {
    const refused = use(MAIL, {}, { text: `${OWN_DENIAL_PREFIX}${MAIL}. It is disabled.`, isError: true })
    assert.deepEqual(rebuild(input({ messages: [assistant([refused])] })).snapshot.labels, [])
    const notError = use(MAIL, {}, { text: `${OWN_DENIAL_PREFIX}imitated` })
    assert.deepEqual(rebuild(input({ messages: [assistant([notError])] })).snapshot.labels, ['private', 'untrusted'])
  })

  it('passes the call to the matcher with its arguments and ids', () => {
    const seen: Array<{ call: ToolCall; timing: Timing }> = []
    rebuild(
      input({
        messages: [assistant([{ tool_use_id: 'toolu_1', tool: 'Read', input: { file_path: '/a/.env' }, text: 'X=1', agentId: 'ag' }])],
        match: (call, timing) => {
          seen.push({ call, timing })
          return matcher(call, timing)
        },
      }),
    )
    assert.deepEqual(seen, [
      { call: { tool: 'Read', args: { file_path: '/a/.env' }, toolUseId: 'toolu_1', agentId: 'ag' }, timing: 'attempt' },
      { call: { tool: 'Read', args: { file_path: '/a/.env' }, toolUseId: 'toolu_1', agentId: 'ag' }, timing: 'success' },
    ])
  })

  it('replays subagent conversations into the shared set', () => {
    const result = rebuild(
      input({
        messages: [assistant([use('Bash', { command: 'ls' }, { text: 'ok' })])],
        agentMessages: [[], [assistant([use(MAIL, {}, { text: 'mail', agentId: 'agent-7' })])]],
      }),
    )
    assert.deepEqual(result.snapshot.labels, ['private', 'untrusted'])
    assert.equal(result.snapshot.firedBy[0]?.agentId, 'agent-7')
  })

  it('takes the union with the store copy', () => {
    const storeCopy = { labels: ['secret'], firedBy: [fire('user:secrets', ['secret'])], savedAt: 1 }
    const result = rebuild(input({ storeCopy, messages: [assistant([use(MAIL, {})])] }))
    assert.deepEqual(result.snapshot.labels, ['private', 'secret', 'untrusted'])
    assert.deepEqual(result.snapshot.firedBy[0], { rule: 'store', tool: '(saved taint)', labels: ['secret'], at: 5000 })
    assert.equal(result.snapshot.firedBy[1]?.rule, 'user:gmail-read')
  })

  it('restores labels from a compaction record with no store copy (spec test 21)', () => {
    const record = formatRecord(['private', 'untrusted'])
    const result = rebuild(input({ messages: [user(`Summary...\n${record}`), user(record)] }))
    assert.deepEqual(result.snapshot.labels, ['private', 'untrusted'])
    assert.equal(result.records.length, 2)
    assert.deepEqual(result.snapshot.firedBy, [{ rule: 'record', tool: '(taint record)', labels: ['private', 'untrusted'], at: 5000 }])
  })

  it('adds labels from an imitated record in a tool result, never removing any (spec test 22)', () => {
    const imitation = `Dear user,\n${RECORD_PREFIX}secret,bogus\nRegards`
    const result = rebuild(
      input({
        base: { labels: ['private'], firedBy: [], blockedCount: 4 },
        messages: [
          assistant([use('Bash', { command: 'cat x' }, { text: 'ok' })]),
          user('', [{ tool_use_id: 'toolu_x', text: imitation, isError: false }]),
        ],
      }),
    )
    assert.deepEqual(result.snapshot.labels, ['private', 'secret'])
    assert.deepEqual(result.added, ['secret'])
    assert.equal(result.snapshot.blockedCount, 4)
    assert.deepEqual(result.records, [{ labels: ['bogus', 'secret'], excerpt: `${RECORD_PREFIX}secret,bogus` }])
  })

  it('scans tool use text and message text for records', () => {
    const result = rebuild(
      input({
        messages: [assistant([use('Bash', {}, { text: formatRecord(['secret']) })], `note ${formatRecord(['untrusted'])}`)],
      }),
    )
    assert.deepEqual(result.snapshot.labels, ['secret', 'untrusted'])
    assert.equal(result.records.length, 2)
  })

  it('collects records that add nothing', () => {
    const result = rebuild(
      input({ base: { labels: ['private'], firedBy: [], blockedCount: 0 }, messages: [user(formatRecord(['private', 'nope']))] }),
    )
    assert.equal(result.records.length, 1)
    assert.deepEqual(result.added, [])
    assert.deepEqual(result.snapshot.firedBy, [])
  })

  it('assumes every label when history may be cut (spec test 14)', () => {
    const messages = Array.from({ length: 4096 }, () => user('hello'))
    const result = rebuild(input({ messages }))
    assert.equal(result.truncated, true)
    assert.deepEqual(result.snapshot.labels, DECLARED)
    assert.deepEqual(result.snapshot.firedBy, [{ rule: 'history-cut', tool: '(history cut)', labels: DECLARED, at: 5000 }])
  })

  it('ignores a cut history when told to', () => {
    const messages = Array.from({ length: 10 }, () => user('hello'))
    const result = rebuild(input({ messages, historyLimit: 10, onUnknownHistory: 'ignore' }))
    assert.equal(result.truncated, true)
    assert.deepEqual(result.snapshot.labels, [])
  })

  it('counts only the main conversation toward the history limit', () => {
    const many = Array.from({ length: 10 }, () => user('hello'))
    const result = rebuild(input({ messages: [], agentMessages: [many], historyLimit: 10 }))
    assert.equal(result.truncated, false)
    assert.deepEqual(result.snapshot.labels, [])
  })

  it('keeps the base and never mutates it', () => {
    const base: TaintSnapshot = { labels: ['secret'], firedBy: [fire('x', ['secret'])], blockedCount: 1 }
    const copy = structuredClone(base)
    const result = rebuild(input({ base, messages: [assistant([use(MAIL, {})])] }))
    assert.deepEqual(base, copy)
    assert.deepEqual(result.snapshot.labels, ['private', 'secret', 'untrusted'])
    assert.deepEqual(result.added, ['private', 'untrusted'])
    assert.equal(result.snapshot.firedBy.length, 2)
  })

  it('rebuilds 4,096 messages of 4 tool uses in under 200 ms', () => {
    const messages: MessageLike[] = []
    for (let i = 0; i < 4096; i++) {
      messages.push(
        assistant(
          [
            use('Bash', { command: `echo ${i}` }, { text: 'ok' }),
            use('Read', { file_path: `/src/file${i}.ts` }, { text: 'content' }),
            use('Grep', { pattern: 'x' }, { text: 'none' }),
            use(i === 4000 ? MAIL : 'Edit', { file_path: '/x' }, { text: 'done' }),
          ],
          `turn ${i}`,
        ),
      )
    }
    const regexes = [/^mcp__gmail__get_/i, /^mcp__.+__read/i, /^WebFetch$/, /\.env$/]
    const match = (call: ToolCall, timing: Timing) => {
      const out: Array<{ id: string; taints: string[] }> = []
      if (timing !== 'attempt') return out
      if (regexes[0]!.test(call.tool) || regexes[1]!.test(call.tool)) out.push({ id: 'p:mail', taints: ['private'] })
      if (regexes[2]!.test(call.tool)) out.push({ id: 'p:web', taints: ['untrusted'] })
      if (regexes[3]!.test(String(call.args.file_path ?? ''))) out.push({ id: 'p:env', taints: ['secret'] })
      return out
    }
    rebuild(input({ messages: messages.slice(0, 100), match, historyLimit: 100000 }))
    const start = performance.now()
    const result = rebuild(input({ messages, match, historyLimit: 100000 }))
    const elapsed = performance.now() - start
    assert.deepEqual(result.snapshot.labels, ['private'])
    assert.ok(elapsed < 200, `rebuild took ${elapsed.toFixed(1)} ms`)
  })
})

describe('store copy', () => {
  const snap: TaintSnapshot = {
    labels: ['private'],
    firedBy: [fire('user:gmail-read', ['private'], { agentId: 'a', toolUseId: 't' })],
    blockedCount: 9,
  }

  it('keys by session id', () => {
    assert.equal(storeKey('abc-123'), 'taint:abc-123')
  })

  it('round-trips through toStored and parseStored', () => {
    const stored = toStored(snap, 42)
    assert.deepEqual(stored, { labels: ['private'], firedBy: snap.firedBy, savedAt: 42 })
    assert.deepEqual(parseStored(JSON.parse(JSON.stringify(stored))), stored)
    assert.notEqual(stored.labels, snap.labels)
  })

  it('rejects malformed values', () => {
    const good = toStored(snap, 42)
    const bad: unknown[] = [
      null,
      undefined,
      'x',
      [],
      42,
      { ...good, labels: 'private' },
      { ...good, labels: [1] },
      { ...good, savedAt: '42' },
      { ...good, savedAt: Number.NaN },
      { labels: good.labels, savedAt: 42 },
      { ...good, firedBy: [null] },
      { ...good, firedBy: [{ rule: 'r', tool: 't', labels: ['a'] }] },
      { ...good, firedBy: [{ rule: 'r', tool: 't', labels: ['a'], at: 1, agentId: 5 }] },
      { ...good, firedBy: [{ rule: 'r', tool: 't', labels: ['a'], at: 1, toolUseId: false }] },
      { ...good, firedBy: [{ rule: 1, tool: 't', labels: ['a'], at: 1 }] },
    ]
    for (const value of bad) assert.equal(parseStored(value), null, JSON.stringify(value))
  })

  it('drops unknown fields when parsing', () => {
    const parsed = parseStored({ labels: ['a'], firedBy: [{ rule: 'r', tool: 't', labels: ['a'], at: 1, extra: 1 }], savedAt: 1, x: 2 })
    assert.deepEqual(parsed, { labels: ['a'], firedBy: [{ rule: 'r', tool: 't', labels: ['a'], at: 1 }], savedAt: 1 })
  })

  it('lists stale and unreadable taint keys only', () => {
    const day = 24 * 60 * 60 * 1000
    const now = 100 * day
    const keys = staleStoreKeys(
      [
        ['taint:fresh', toStored(snap, now - day)],
        ['taint:edge', toStored(snap, now - 14 * day)],
        ['taint:old', toStored(snap, now - 15 * day)],
        ['taint:broken', { nope: true }],
        ['audit-key', 'abcd'],
        ['other:old', toStored(snap, 0)],
      ],
      now,
    )
    assert.deepEqual(keys, ['taint:old', 'taint:broken'])
    assert.deepEqual(staleStoreKeys([['taint:fresh', toStored(snap, now - 2 * day)]], now, day), ['taint:fresh'])
  })
})

describe('declassification cut point', () => {
  const mail = use(MAIL, {}, { tool_use_id: 'toolu_mail', text: 'mail' })
  const read = use('Read', { file_path: '/repo/.env' }, { tool_use_id: 'toolu_env', text: 'X=1' })
  const later = use(MAIL, {}, { tool_use_id: 'toolu_later', text: 'more mail' })

  it('lastToolUseId names the newest tool use', () => {
    assert.equal(lastToolUseId([assistant([mail, read]), user('ok')]), 'toolu_env')
    assert.equal(lastToolUseId([user('hi')]), undefined)
  })

  it('round-trips clearedThrough through the store copy', () => {
    const stored = toStored(EMPTY_TAINT, 5, 'toolu_env')
    assert.deepEqual(parseStored(JSON.parse(JSON.stringify(stored))), stored)
    assert.equal(parseStored({ ...stored, clearedThrough: 3 }), null)
  })

  it('skips the history a declassification covered', () => {
    const storeCopy = toStored(EMPTY_TAINT, 5, 'toolu_env')
    const result = rebuild(input({ messages: [assistant([mail, read]), user(formatRecord(['secret']))], storeCopy }))
    assert.deepEqual(result.snapshot.labels, ['secret'])
    const none = rebuild(input({ messages: [assistant([mail, read])], storeCopy }))
    assert.deepEqual(none.snapshot.labels, [])
  })

  it('replays sources after the cut', () => {
    const storeCopy = toStored(EMPTY_TAINT, 5, 'toolu_env')
    const result = rebuild(input({ messages: [assistant([mail, read]), user('ok'), assistant([later])], storeCopy }))
    assert.deepEqual(result.snapshot.labels, ['private', 'untrusted'])
  })

  it('scans everything when the cut point is no longer in the history', () => {
    const storeCopy = toStored(EMPTY_TAINT, 5, 'toolu_compacted_away')
    const result = rebuild(input({ messages: [assistant([mail, read])], storeCopy }))
    assert.deepEqual(result.snapshot.labels, ['private', 'secret', 'untrusted'])
  })
})
