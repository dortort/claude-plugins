import type {
  Action,
  ActiveSummary,
  ArgumentPredicate,
  CompiledPolicy,
  CompiledSink,
  CompiledSource,
  LayerName,
  LayerStatus,
  LoadedPolicy,
  LoadInput,
  Matcher,
  Mode,
  PolicyFile,
  PresetName,
  RuleRef,
  SinkDecision,
  SinkMatch,
  SinkRule,
  SourceRule,
  Timing,
  ToolCall,
  ToolMatch,
  ToolSelector,
  ValidationResult,
} from './types.ts'
import { ACTION_ORDER, DECLASSIFY_ORDER, MODE_ORDER, UNKNOWN_HISTORY_ORDER } from './types.ts'

const LABEL_NAME = /^[A-Za-z0-9-]{1,32}$/
const RULE_ID = /^[A-Za-z0-9._-]{1,64}$/
const RULE_REF = /^(preset|managed|user|project):[A-Za-z0-9._-]{1,64}$/
const REGEX_TEXT_CAP = 100_000
const REASON_MAX = 1000
const PROJECT_REGEX_LENGTH_MAX = 256
const PROJECT_REGEX_COUNT_MAX = 50
const MERGE_ORDER: readonly LayerName[] = ['managed', 'user', 'project', 'preset']
const STATUS_ORDER: readonly LayerName[] = ['preset', 'managed', 'user', 'project']

const TOP_KEYS = [
  '$schema',
  'version',
  'description',
  'mode',
  'subagents',
  'resetOnClear',
  'userDeclassify',
  'onUnknownHistory',
  'labels',
  'sources',
  'sinks',
] as const
const SOURCE_KEYS = ['id', 'description', 'match', 'on', 'taints', 'enabled'] as const
const SINK_KEYS = ['id', 'description', 'when', 'block', 'except', 'action', 'reason', 'enabled'] as const
const SELECTOR_KINDS = ['exact', 'prefix', 'regex', 'anyOf'] as const
const PREDICATE_KINDS = ['equals', 'matches', 'notMatches', 'exists'] as const

type Obj = Record<string, unknown>
type Ctx = { errors: string[]; untrusted: boolean; regexes: number }
type SelectorKind = (typeof SELECTOR_KINDS)[number]

function isObject(value: unknown): value is Obj {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function has(obj: Obj, key: string): boolean {
  return Object.hasOwn(obj, key) && obj[key] !== undefined
}

function at(path: string, key: string | number): string {
  if (typeof key === 'number') return `${path}[${key}]`
  return path === '' ? key : `${path}.${key}`
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error)
}

function fail(ctx: Ctx, path: string, message: string): void {
  ctx.errors.push(`${path === '' ? '(root)' : path}: ${message}`)
}

function checkKeys(ctx: Ctx, obj: Obj, path: string, allowed: readonly string[]): void {
  for (const key of Object.keys(obj)) {
    if (!allowed.includes(key)) fail(ctx, at(path, key), 'unknown key')
  }
}

function checkEnum(ctx: Ctx, value: unknown, path: string, allowed: readonly string[]): void {
  if (typeof value !== 'string' || !allowed.includes(value)) {
    fail(ctx, path, `must be one of ${allowed.join(', ')}`)
  }
}

function checkString(ctx: Ctx, value: unknown, path: string): void {
  if (typeof value !== 'string') fail(ctx, path, 'must be a string')
}

function checkNonEmptyString(ctx: Ctx, value: unknown, path: string): void {
  if (typeof value !== 'string' || value === '') fail(ctx, path, 'must be a non-empty string')
}

function checkBoolean(ctx: Ctx, value: unknown, path: string): void {
  if (typeof value !== 'boolean') fail(ctx, path, 'must be a boolean')
}

function checkRegex(ctx: Ctx, value: unknown, flags: unknown, path: string): void {
  if (typeof value !== 'string') {
    fail(ctx, path, 'must be a string')
    return
  }
  try {
    new RegExp(value, flags === 'i' ? 'i' : '')
  } catch (error) {
    fail(ctx, path, `invalid regex: ${messageOf(error)}`)
    return
  }
  if (!ctx.untrusted) return
  ctx.regexes++
  if (value.length > PROJECT_REGEX_LENGTH_MAX) {
    fail(ctx, path, `a regex in a project policy must be at most ${PROJECT_REGEX_LENGTH_MAX} characters`)
  }
  if (hasNestedQuantifier(value)) fail(ctx, path, 'nested unbounded quantifiers are not allowed in a project policy')
  if (hasQuantifiedAlternation(value)) {
    fail(ctx, path, 'alternation under an unbounded quantifier is not allowed in a project policy')
  }
}

function isJsonValue(value: unknown): boolean {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return true
  if (typeof value === 'number') return Number.isFinite(value)
  if (Array.isArray(value)) return value.every(isJsonValue)
  if (isObject(value)) return Object.values(value).every(isJsonValue)
  return false
}

function checkLabelList(ctx: Ctx, value: unknown, path: string, nonEmpty: boolean): void {
  if (!Array.isArray(value)) {
    fail(ctx, path, 'must be an array of label names')
    return
  }
  if (nonEmpty && value.length === 0) fail(ctx, path, 'must name at least one label')
  const seen = new Set<string>()
  value.forEach((name, i) => {
    if (typeof name !== 'string' || !LABEL_NAME.test(name)) {
      fail(ctx, at(path, i), 'must be a label name')
    } else if (seen.has(name)) {
      fail(ctx, at(path, i), `duplicate label '${name}'`)
    } else {
      seen.add(name)
    }
  })
}

function checkSelector(ctx: Ctx, selector: unknown, path: string): void {
  if (!isObject(selector)) {
    fail(ctx, path, 'must be an object')
    return
  }
  checkKeys(ctx, selector, path, [...SELECTOR_KINDS, 'flags'])
  const kinds = SELECTOR_KINDS.filter((kind) => has(selector, kind))
  if (kinds.length !== 1) fail(ctx, path, 'exactly one of exact, prefix, regex, anyOf')
  if (has(selector, 'exact')) checkNonEmptyString(ctx, selector.exact, at(path, 'exact'))
  if (has(selector, 'prefix')) checkNonEmptyString(ctx, selector.prefix, at(path, 'prefix'))
  if (has(selector, 'regex')) checkRegex(ctx, selector.regex, selector.flags, at(path, 'regex'))
  if (has(selector, 'anyOf')) {
    const anyOf = selector.anyOf
    if (!Array.isArray(anyOf) || anyOf.length === 0) {
      fail(ctx, at(path, 'anyOf'), 'must be a non-empty array of tool names')
    } else {
      anyOf.forEach((name, i) => checkNonEmptyString(ctx, name, at(at(path, 'anyOf'), i)))
    }
  }
  if (has(selector, 'flags')) {
    if (selector.flags !== 'i') fail(ctx, at(path, 'flags'), "the only flag is 'i'")
    else if (!has(selector, 'prefix') && !has(selector, 'regex')) {
      fail(ctx, at(path, 'flags'), 'allowed only with prefix or regex')
    }
  }
}

function checkPredicate(ctx: Ctx, predicate: unknown, path: string): void {
  if (!isObject(predicate)) {
    fail(ctx, path, 'must be an object')
    return
  }
  checkKeys(ctx, predicate, path, ['pointer', 'flags', ...PREDICATE_KINDS])
  if (!has(predicate, 'pointer')) fail(ctx, at(path, 'pointer'), 'required')
  else if (typeof predicate.pointer !== 'string') fail(ctx, at(path, 'pointer'), 'must be a string')
  else if (predicate.pointer !== '' && !predicate.pointer.startsWith('/')) {
    fail(ctx, at(path, 'pointer'), "must be '' or start with /")
  }
  const kinds = PREDICATE_KINDS.filter((kind) => Object.hasOwn(predicate, kind))
  if (kinds.length !== 1) fail(ctx, path, 'exactly one of equals, matches, notMatches, exists')
  if (Object.hasOwn(predicate, 'equals') && !isJsonValue(predicate.equals)) {
    fail(ctx, at(path, 'equals'), 'must be a JSON value')
  }
  if (has(predicate, 'matches')) checkRegex(ctx, predicate.matches, predicate.flags, at(path, 'matches'))
  if (has(predicate, 'notMatches')) checkRegex(ctx, predicate.notMatches, predicate.flags, at(path, 'notMatches'))
  if (has(predicate, 'exists')) checkBoolean(ctx, predicate.exists, at(path, 'exists'))
  if (has(predicate, 'flags')) {
    if (predicate.flags !== 'i') fail(ctx, at(path, 'flags'), "the only flag is 'i'")
    else if (!has(predicate, 'matches') && !has(predicate, 'notMatches')) {
      fail(ctx, at(path, 'flags'), 'allowed only with matches or notMatches')
    }
  }
}

function checkMatcher(ctx: Ctx, matcher: unknown, path: string): void {
  if (!isObject(matcher)) {
    fail(ctx, path, 'must be an object')
    return
  }
  checkKeys(ctx, matcher, path, ['tool', 'arguments'])
  if (!has(matcher, 'tool')) fail(ctx, at(path, 'tool'), 'required')
  else checkSelector(ctx, matcher.tool, at(path, 'tool'))
  if (has(matcher, 'arguments')) {
    const args = matcher.arguments
    if (!Array.isArray(args)) fail(ctx, at(path, 'arguments'), 'must be an array')
    else args.forEach((predicate, i) => checkPredicate(ctx, predicate, at(at(path, 'arguments'), i)))
  }
}

function checkMatcherList(ctx: Ctx, value: unknown, path: string, nonEmpty: boolean): void {
  if (!Array.isArray(value)) {
    fail(ctx, path, 'must be an array of matchers')
    return
  }
  if (nonEmpty && value.length === 0) fail(ctx, path, 'must hold at least one matcher')
  value.forEach((matcher, i) => checkMatcher(ctx, matcher, at(path, i)))
}

function isReference(entry: Obj): boolean {
  return typeof entry.id === 'string' && entry.id.includes(':')
}

function checkEntry(ctx: Ctx, entry: unknown, path: string, kind: 'source' | 'sink', ids: Map<string, string>): void {
  if (!isObject(entry)) {
    fail(ctx, path, 'must be an object')
    return
  }
  if (isReference(entry)) {
    if (!RULE_REF.test(entry.id as string)) {
      fail(ctx, at(path, 'id'), 'a reference is <layer>:<id> with layer preset, managed, user or project')
    }
    const keys = Object.keys(entry)
    if (keys.length !== 2 || !keys.includes('enabled') || entry.enabled !== false) {
      fail(ctx, path, 'a reference to a rule has exactly the keys id and enabled: false')
    }
    return
  }
  if (!has(entry, 'id')) fail(ctx, at(path, 'id'), 'required')
  else if (typeof entry.id !== 'string' || !RULE_ID.test(entry.id)) {
    fail(ctx, at(path, 'id'), 'must be letters, digits, ., _ or -, 1-64 characters')
  } else {
    const first = ids.get(entry.id)
    if (first !== undefined) fail(ctx, at(path, 'id'), `duplicate id '${entry.id}' (also ${first})`)
    else ids.set(entry.id, path)
  }
  if (has(entry, 'description')) checkString(ctx, entry.description, at(path, 'description'))
  if (has(entry, 'enabled')) checkBoolean(ctx, entry.enabled, at(path, 'enabled'))
  if (kind === 'source') {
    checkKeys(ctx, entry, path, SOURCE_KEYS)
    if (!has(entry, 'match')) fail(ctx, at(path, 'match'), 'required')
    else checkMatcher(ctx, entry.match, at(path, 'match'))
    if (has(entry, 'on')) checkEnum(ctx, entry.on, at(path, 'on'), ['attempt', 'success'])
    if (!has(entry, 'taints')) fail(ctx, at(path, 'taints'), 'required')
    else checkLabelList(ctx, entry.taints, at(path, 'taints'), true)
    return
  }
  checkKeys(ctx, entry, path, SINK_KEYS)
  if (!has(entry, 'when')) fail(ctx, at(path, 'when'), 'required')
  else if (!isObject(entry.when)) fail(ctx, at(path, 'when'), 'must be an object')
  else {
    const when = entry.when
    checkKeys(ctx, when, at(path, 'when'), ['anyOf', 'allOf'])
    if (has(when, 'anyOf')) checkLabelList(ctx, when.anyOf, at(at(path, 'when'), 'anyOf'), false)
    if (has(when, 'allOf')) checkLabelList(ctx, when.allOf, at(at(path, 'when'), 'allOf'), false)
  }
  if (!has(entry, 'block')) fail(ctx, at(path, 'block'), 'required')
  else checkMatcherList(ctx, entry.block, at(path, 'block'), true)
  if (has(entry, 'except')) checkMatcherList(ctx, entry.except, at(path, 'except'), false)
  if (has(entry, 'action')) checkEnum(ctx, entry.action, at(path, 'action'), ['deny', 'ask', 'audit'])
  if (has(entry, 'reason')) {
    if (typeof entry.reason !== 'string') fail(ctx, at(path, 'reason'), 'must be a string')
    else if (entry.reason.length > REASON_MAX) fail(ctx, at(path, 'reason'), `must be at most ${REASON_MAX} characters`)
  }
}

/** Structural validation of one policy layer; label references are checked by loadPolicy. */
export function validatePolicy(value: unknown, options?: { layer?: LayerName }): ValidationResult {
  const ctx: Ctx = { errors: [], untrusted: options?.layer === 'project', regexes: 0 }
  if (!isObject(value)) return { ok: false, errors: ['(root): must be an object'] }
  checkKeys(ctx, value, '', TOP_KEYS)
  if (has(value, '$schema')) checkString(ctx, value.$schema, '$schema')
  if (!has(value, 'version')) fail(ctx, 'version', 'required')
  else if (value.version !== 1) fail(ctx, 'version', 'unknown version')
  if (has(value, 'description')) checkString(ctx, value.description, 'description')
  if (has(value, 'mode')) checkEnum(ctx, value.mode, 'mode', MODE_ORDER)
  if (has(value, 'subagents')) {
    if (value.subagents === 'per-agent') fail(ctx, 'subagents', 'per-agent is reserved for v1.1')
    else if (value.subagents !== 'shared') fail(ctx, 'subagents', 'must be shared')
  }
  if (has(value, 'resetOnClear')) checkBoolean(ctx, value.resetOnClear, 'resetOnClear')
  if (has(value, 'userDeclassify')) checkEnum(ctx, value.userDeclassify, 'userDeclassify', DECLASSIFY_ORDER)
  if (has(value, 'onUnknownHistory')) checkEnum(ctx, value.onUnknownHistory, 'onUnknownHistory', UNKNOWN_HISTORY_ORDER)
  if (!has(value, 'labels')) fail(ctx, 'labels', 'required')
  else if (!isObject(value.labels)) fail(ctx, 'labels', 'must be an object')
  else {
    const labels = value.labels
    if (Object.keys(labels).length === 0) fail(ctx, 'labels', 'must declare at least one label')
    for (const [name, label] of Object.entries(labels)) {
      const path = at('labels', name)
      if (!LABEL_NAME.test(name)) fail(ctx, path, 'label names are letters, digits and -, 1-32 characters')
      if (!isObject(label)) {
        fail(ctx, path, 'must be an object')
        continue
      }
      checkKeys(ctx, label, path, ['description'])
      if (has(label, 'description')) checkString(ctx, label.description, at(path, 'description'))
    }
  }
  const ids = new Map<string, string>()
  for (const kind of ['source', 'sink'] as const) {
    const key = kind === 'source' ? 'sources' : 'sinks'
    if (!has(value, key)) continue
    const list = value[key]
    if (!Array.isArray(list)) {
      fail(ctx, key, 'must be an array')
      continue
    }
    list.forEach((entry, i) => checkEntry(ctx, entry, at(key, i), kind, ids))
  }
  if (ctx.regexes > PROJECT_REGEX_COUNT_MAX) {
    fail(ctx, '', `a project policy may hold at most ${PROJECT_REGEX_COUNT_MAX} regexes; this one has ${ctx.regexes}`)
  }
  return ctx.errors.length === 0 ? { ok: true, policy: value as PolicyFile } : { ok: false, errors: ctx.errors }
}

function readQuantifier(source: string, i: number): { unbounded: boolean; end: number } | null {
  const c = source[i]
  if (c === '*' || c === '+') return { unbounded: true, end: i + 1 }
  if (c === '?') return { unbounded: false, end: i + 1 }
  if (c !== '{') return null
  const m = /^\{(\d+)(,(\d*))?\}/.exec(source.slice(i))
  if (m === null) return null
  return { unbounded: m[2] !== undefined && m[3] === '', end: i + m[0].length }
}

/** True when a group containing an unbounded quantifier is itself unboundedly quantified. */
export function hasNestedQuantifier(source: string): boolean {
  const stack: boolean[] = [false]
  let i = 0
  const markUnbounded = (): void => {
    stack[stack.length - 1] = true
  }
  const afterAtom = (): void => {
    const q = readQuantifier(source, i)
    if (q === null) return
    if (q.unbounded) markUnbounded()
    i = q.end
    if (source[i] === '?') i++
  }
  while (i < source.length) {
    const c = source[i]
    if (c === '\\') {
      i += 2
      afterAtom()
    } else if (c === '[') {
      i++
      while (i < source.length && source[i] !== ']') i += source[i] === '\\' ? 2 : 1
      i++
      afterAtom()
    } else if (c === '(') {
      i++
      if (source[i] === '?') {
        i++
        if (source[i] === '<' && source[i + 1] !== '=' && source[i + 1] !== '!') {
          const close = source.indexOf('>', i)
          i = close === -1 ? source.length : close + 1
        } else {
          i += source[i] === '<' ? 2 : 1
        }
      }
      stack.push(false)
    } else if (c === ')') {
      i++
      const inner = stack.length > 1 ? (stack.pop() as boolean) : false
      const q = readQuantifier(source, i)
      if (q !== null) {
        if (q.unbounded && inner) return true
        i = q.end
        if (source[i] === '?') i++
      }
      if (inner || q?.unbounded === true) markUnbounded()
    } else {
      i++
      afterAtom()
    }
  }
  return false
}

/** True when a group with a top-level | is followed by an unbounded quantifier, as in (a|aa)+. */
export function hasQuantifiedAlternation(source: string): boolean {
  const stack: boolean[] = [false]
  let i = 0
  while (i < source.length) {
    const c = source[i]
    if (c === '\\') {
      i += 2
    } else if (c === '[') {
      i++
      while (i < source.length && source[i] !== ']') i += source[i] === '\\' ? 2 : 1
      i++
    } else if (c === '(') {
      i++
      stack.push(false)
    } else if (c === ')') {
      i++
      const alternation = stack.length > 1 ? (stack.pop() as boolean) : false
      if (alternation && readQuantifier(source, i)?.unbounded === true) return true
    } else {
      if (c === '|') stack[stack.length - 1] = true
      i++
    }
  }
  return false
}

/** RFC 6901 JSON Pointer lookup. */
export function resolvePointer(args: unknown, pointer: string): { found: boolean; value?: unknown } {
  if (pointer === '') return { found: true, value: args }
  if (!pointer.startsWith('/')) return { found: false }
  let current: unknown = args
  for (const raw of pointer.slice(1).split('/')) {
    const token = raw.replace(/~1/g, '/').replace(/~0/g, '~')
    if (Array.isArray(current)) {
      if (!/^(0|[1-9]\d*)$/.test(token)) return { found: false }
      const index = Number(token)
      if (index >= current.length) return { found: false }
      current = current[index]
    } else if (isObject(current)) {
      if (!Object.hasOwn(current, token)) return { found: false }
      current = current[token]
    } else {
      return { found: false }
    }
    if (current === undefined) return { found: false }
  }
  return { found: true, value: current }
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true
  if (Array.isArray(a)) {
    return Array.isArray(b) && a.length === b.length && a.every((item, i) => deepEqual(item, b[i]))
  }
  if (isObject(a) && isObject(b)) {
    const keys = Object.keys(a).filter((key) => a[key] !== undefined)
    const otherKeys = Object.keys(b).filter((key) => b[key] !== undefined)
    return keys.length === otherKeys.length && keys.every((key) => Object.hasOwn(b, key) && deepEqual(a[key], b[key]))
  }
  return false
}

function capped(text: string): string {
  return text.length > REGEX_TEXT_CAP ? text.slice(0, REGEX_TEXT_CAP) : text
}

function textOf(value: unknown): string {
  if (typeof value === 'string') return value
  return JSON.stringify(value) ?? String(value)
}

/** Where a matcher sits: over-long text makes a block or source predicate hold and an except predicate fail. */
export type MatcherRole = 'block' | 'source' | 'except'

function compilePredicate(predicate: ArgumentPredicate, role: MatcherRole): (args: unknown) => boolean {
  const { pointer } = predicate
  if ('equals' in predicate) {
    const expected = predicate.equals
    return (args) => {
      const r = resolvePointer(args, pointer)
      return r.found && deepEqual(r.value, expected)
    }
  }
  if ('exists' in predicate) {
    const expected = predicate.exists
    return (args) => resolvePointer(args, pointer).found === expected
  }
  const negate = 'notMatches' in predicate
  const re = new RegExp('matches' in predicate ? predicate.matches : predicate.notMatches, predicate.flags ?? '')
  const overCap = role !== 'except'
  return (args) => {
    const r = resolvePointer(args, pointer)
    if (!r.found) return negate
    const text = textOf(r.value)
    if (text.length > REGEX_TEXT_CAP) return overCap
    return re.test(text) !== negate
  }
}

export type CompiledMatcher = {
  test(call: ToolCall): boolean
  testTool(tool: string): ToolMatch
  names: string[]
  patterns: string[]
}

type MatcherParts = CompiledMatcher & { kind: SelectorKind; matchesName: (tool: string) => boolean }

function selectorKind(selector: ToolSelector): SelectorKind {
  if ('exact' in selector) return 'exact'
  if ('prefix' in selector) return 'prefix'
  if ('regex' in selector) return 'regex'
  return 'anyOf'
}

function compileSelector(selector: ToolSelector): { kind: SelectorKind; matchesName: (tool: string) => boolean; names: string[]; patterns: string[] } {
  if ('exact' in selector) {
    const name = selector.exact
    return { kind: 'exact', matchesName: (tool) => tool === name, names: [name], patterns: [] }
  }
  if ('prefix' in selector) {
    const insensitive = selector.flags === 'i'
    const prefix = insensitive ? selector.prefix.toLowerCase() : selector.prefix
    return {
      kind: 'prefix',
      matchesName: insensitive ? (tool) => tool.toLowerCase().startsWith(prefix) : (tool) => tool.startsWith(prefix),
      names: [],
      patterns: [`${selector.prefix}…`],
    }
  }
  if ('regex' in selector) {
    const re = new RegExp(selector.regex, selector.flags ?? '')
    return { kind: 'regex', matchesName: (tool) => re.test(capped(tool)), names: [], patterns: [`/${selector.regex}/${selector.flags ?? ''}`] }
  }
  const names = new Set(selector.anyOf)
  return { kind: 'anyOf', matchesName: (tool) => names.has(tool), names: [...names], patterns: [] }
}

function buildMatcher(matcher: Matcher, role: MatcherRole): MatcherParts {
  const selector = compileSelector(matcher.tool)
  const predicates = (matcher.arguments ?? []).map((predicate) => compilePredicate(predicate, role))
  const { matchesName } = selector
  const hasPredicates = predicates.length > 0
  return {
    kind: selector.kind,
    matchesName,
    names: selector.names,
    patterns: selector.patterns,
    test: (call) => matchesName(call.tool) && predicates.every((p) => p(call.args)),
    testTool: (tool) => (matchesName(tool) ? (hasPredicates ? 'maybe' : 'yes') : 'no'),
  }
}

/** Compiles a matcher's selector and argument predicates once. */
export function compileMatcher(m: Matcher, role: MatcherRole = 'block'): CompiledMatcher {
  return buildMatcher(m, role)
}

type SinkParts = { block: MatcherParts[]; except: MatcherParts[] }
const sinkParts = new WeakMap<CompiledSink, SinkParts>()

function best(results: ToolMatch[]): ToolMatch {
  if (results.includes('yes')) return 'yes'
  return results.includes('maybe') ? 'maybe' : 'no'
}

function joinNames(names: readonly string[], word: string): string {
  if (names.length <= 1) return names.join('')
  return `${names.slice(0, -1).join(', ')} ${word} ${names[names.length - 1]}`
}

function defaultReason(anyOf: readonly string[], allOf: readonly string[]): string {
  const parts: string[] = []
  if (allOf.length > 0) parts.push(`${joinNames(allOf, 'and')} content`)
  if (anyOf.length > 0) parts.push(`${joinNames(anyOf, 'or')} content`)
  if (parts.length === 0) return 'This tool is blocked by TaintGuard policy.'
  return `This tool is blocked while the session holds ${parts.join(' together with ')}.`
}

function applyMode(declared: Action, mode: Mode): Action {
  if (mode === 'audit') return 'audit'
  if (mode === 'ask' && declared === 'deny') return 'ask'
  return declared
}

function compileSource(layer: LayerName, rule: SourceRule): CompiledSource {
  const matcher = buildMatcher(rule.match, 'source')
  const source: CompiledSource = {
    id: `${layer}:${rule.id}`,
    layer,
    on: rule.on ?? 'attempt',
    taints: [...rule.taints],
    trusted: layer !== 'project',
    test: matcher.test,
    testTool: matcher.testTool,
  }
  if (rule.description !== undefined) source.description = rule.description
  return source
}

function compileSink(layer: LayerName, rule: SinkRule, mode: Mode): CompiledSink {
  const block = rule.block.map((m) => buildMatcher(m, 'block'))
  const except = (rule.except ?? []).map((m) => buildMatcher(m, 'except'))
  const anyOf = [...(rule.when.anyOf ?? [])]
  const allOf = [...(rule.when.allOf ?? [])]
  const declared = rule.action ?? 'deny'
  const sink: CompiledSink = {
    id: `${layer}:${rule.id}`,
    layer,
    when: { anyOf, allOf },
    declared,
    action: applyMode(declared, mode),
    reason: rule.reason ?? defaultReason(anyOf, allOf),
    trusted: layer !== 'project',
    test: (call) => block.some((m) => m.test(call)) && !except.some((m) => m.test(call)),
    testTool: (tool) => {
      const blocked = best(block.map((m) => m.testTool(tool)))
      if (blocked === 'no') return 'no'
      const excepted = best(except.map((m) => m.testTool(tool)))
      if (excepted === 'yes') return 'no'
      return excepted === 'maybe' ? 'maybe' : blocked
    },
    names: [...new Set(block.flatMap((m) => m.names))],
    patterns: [...new Set(block.flatMap((m) => m.patterns))],
  }
  if (rule.description !== undefined) sink.description = rule.description
  sinkParts.set(sink, { block, except })
  return sink
}

type ValidLayer = { layer: LayerName; path: string | null; policy: PolicyFile }
type RuleEntry =
  | { kind: 'source'; layer: LayerName; rule: SourceRule; enabled: boolean }
  | { kind: 'sink'; layer: LayerName; rule: SinkRule; enabled: boolean }

function isRuleRef(entry: SourceRule | SinkRule | RuleRef): entry is RuleRef {
  return RULE_REF.test(entry.id)
}

function firstUnknownLabel(policy: PolicyFile, declared: ReadonlySet<string>): string | null {
  const check = (names: readonly string[] | undefined, path: string): string | null => {
    const index = (names ?? []).findIndex((name) => !declared.has(name))
    return index === -1 ? null : `unknown label '${(names ?? [])[index]}' at ${path}[${index}]`
  }
  for (const [i, entry] of (policy.sources ?? []).entries()) {
    if (isRuleRef(entry)) continue
    const found = check(entry.taints, `sources[${i}].taints`)
    if (found !== null) return found
  }
  for (const [i, entry] of (policy.sinks ?? []).entries()) {
    if (isRuleRef(entry)) continue
    const found = check(entry.when.anyOf, `sinks[${i}].when.anyOf`) ?? check(entry.when.allOf, `sinks[${i}].when.allOf`)
    if (found !== null) return found
  }
  return null
}

function canDisable(actor: LayerName, target: LayerName, presetFromManaged: boolean): boolean {
  if (actor === target || actor === 'managed') return true
  if (actor === 'user') return target === 'project' || (target === 'preset' && !presetFromManaged)
  return false
}

function strictest<T>(order: readonly T[], values: ReadonlyArray<T | undefined>): T | undefined {
  let winner: T | undefined
  for (const value of values) {
    if (value === undefined) continue
    if (winner === undefined || order.indexOf(value) > order.indexOf(winner)) winner = value
  }
  return winner
}

/** Validates, merges and compiles the preset, managed, user and project layers. */
export function loadPolicy(input: LoadInput, presets: Readonly<Record<PresetName, PolicyFile | null>>): LoadedPolicy {
  const warnings = [...(input.warnings ?? [])]
  const statuses = new Map<LayerName, LayerStatus>()
  let lockdown: string | null =
    input.managedReadError !== undefined ? `cannot read managed settings: ${input.managedReadError}` : null

  const reject = (layer: LayerName, path: string | null, error: string): void => {
    if (layer === 'project') {
      statuses.set(layer, { layer, path, status: 'dropped', rules: 0, error })
      warnings.push(`project policy ${path ?? ''} dropped: ${error}`)
      return
    }
    statuses.set(layer, { layer, path, status: 'invalid', rules: 0, error })
    lockdown ??= `${layer} policy ${path ?? ''}: ${error}`
  }

  const candidates: ValidLayer[] = []
  const presetPolicy = presets[input.preset]
  if (presetPolicy === null || presetPolicy === undefined) {
    statuses.set('preset', { layer: 'preset', path: null, status: 'absent', rules: 0 })
  } else {
    const path = `presets/${input.preset}.json`
    const result = validatePolicy(presetPolicy, { layer: 'preset' })
    if (result.ok) candidates.push({ layer: 'preset', path, policy: result.policy })
    else reject('preset', path, result.errors[0] ?? 'invalid')
  }

  const files = [
    ['managed', input.managed],
    ['user', input.user],
    ['project', input.project],
  ] as const
  for (const [layer, file] of files) {
    if (file === null) continue
    const { path } = file
    if (file.readError !== undefined) {
      reject(layer, path, `cannot read: ${file.readError}`)
      continue
    }
    if (file.text === null && layer === 'managed') {
      reject(layer, path, 'file not found')
      continue
    }
    if (file.text === null) {
      statuses.set(layer, { layer, path, status: 'absent', rules: 0 })
      continue
    }
    let parsed: unknown
    try {
      parsed = JSON.parse(file.text)
    } catch (error) {
      reject(layer, path, `invalid JSON: ${messageOf(error)}`)
      continue
    }
    const result = validatePolicy(parsed, { layer })
    if (result.ok) candidates.push({ layer, path, policy: result.policy })
    else reject(layer, path, result.errors[0] ?? 'invalid')
  }

  let valid = candidates
  for (;;) {
    const declared = new Set(valid.flatMap((l) => Object.keys(l.policy.labels)))
    const kept = valid.filter((l) => {
      const unknown = firstUnknownLabel(l.policy, declared)
      if (unknown === null) return true
      reject(l.layer, l.path, unknown)
      return false
    })
    if (kept.length === valid.length) break
    valid = kept
  }
  const ordered = MERGE_ORDER.flatMap((name) => valid.filter((l) => l.layer === name))

  const entries = new Map<string, RuleEntry>()
  const refs: Array<{ actor: LayerName; id: string }> = []
  for (const { layer, policy } of ordered) {
    for (const rule of policy.sources ?? []) {
      if (isRuleRef(rule)) refs.push({ actor: layer, id: rule.id })
      else entries.set(`${layer}:${rule.id}`, { kind: 'source', layer, rule, enabled: rule.enabled !== false })
    }
    for (const rule of policy.sinks ?? []) {
      if (isRuleRef(rule)) refs.push({ actor: layer, id: rule.id })
      else entries.set(`${layer}:${rule.id}`, { kind: 'sink', layer, rule, enabled: rule.enabled !== false })
    }
  }
  for (const { actor, id } of refs) {
    const target = entries.get(id)
    if (target === undefined) warnings.push(`${actor} policy refers to unknown rule ${id}; nothing disabled`)
    else if (canDisable(actor, target.layer, input.presetFromManaged)) target.enabled = false
    else warnings.push(`${actor} policy cannot disable ${id}; the rule stays on`)
  }

  const byLayer = (name: LayerName): PolicyFile | undefined => ordered.find((l) => l.layer === name)?.policy
  const managedFloor = input.managedFloor === true || input.presetFromManaged
  const floorLayers: readonly LayerName[] = managedFloor ? ['managed', 'preset'] : ['managed', 'user', 'preset']
  const floorPolicies = ordered.filter((l) => floorLayers.includes(l.layer)).map((l) => l.policy)
  const raised = <T extends string>(order: readonly T[], floor: T, layer: LayerName, pick: (p: PolicyFile) => T | undefined, warning: string): T => {
    const policy = byLayer(layer)
    const own = policy === undefined ? undefined : pick(policy)
    if (own === undefined) return floor
    if (order.indexOf(own) < order.indexOf(floor)) {
      warnings.push(warning)
      return floor
    }
    return own
  }
  const tightened = <T extends string>(key: string, order: readonly T[], fallback: T, pick: (p: PolicyFile) => T | undefined): T => {
    const base = strictest(order, floorPolicies.map(pick)) ?? fallback
    const floor = managedFloor
      ? raised(order, base, 'user', pick, `user policy cannot lower ${key} below the managed floor; the value is ignored`)
      : base
    return raised(order, floor, 'project', pick, `project policy cannot lower ${key}; the value is ignored`)
  }
  const declaredMode = tightened('mode', MODE_ORDER, 'enforce', (p) => p.mode)
  const mode: Mode = lockdown === null ? declaredMode : 'enforce'
  const userDeclassify = tightened('userDeclassify', DECLASSIFY_ORDER, 'confirm', (p) => p.userDeclassify)
  const declassifier = ordered.find((l) => l.policy.userDeclassify === userDeclassify)
  const onUnknownHistory = tightened('onUnknownHistory', UNKNOWN_HISTORY_ORDER, 'assume-tainted', (p) => p.onUnknownHistory)
  const projectReset = byLayer('project')?.resetOnClear
  if (projectReset !== undefined) warnings.push('project policy cannot set resetOnClear; the value is ignored')
  const resetOnClear = byLayer('managed')?.resetOnClear ?? byLayer('user')?.resetOnClear ?? true

  const labels: Record<string, { description?: string; layer: LayerName }> = {}
  const addLabels = (layer: LayerName, policy: PolicyFile): void => {
    for (const [name, label] of Object.entries(policy.labels)) {
      if (Object.hasOwn(labels, name)) continue
      labels[name] = label.description === undefined ? { layer } : { description: label.description, layer }
    }
  }
  for (const { layer, policy } of ordered) addLabels(layer, policy)

  const sources: CompiledSource[] = []
  const sinks: CompiledSink[] = []
  const counts = new Map<LayerName, number>()
  for (const entry of entries.values()) {
    if (!entry.enabled) continue
    counts.set(entry.layer, (counts.get(entry.layer) ?? 0) + 1)
    if (entry.kind === 'source') sources.push(compileSource(entry.layer, entry.rule))
    else sinks.push(compileSink(entry.layer, entry.rule, mode))
  }

  if (lockdown !== null) {
    const strict = presets.strict
    if (strict !== null && strict !== undefined && validatePolicy(strict, { layer: 'preset' }).ok) {
      addLabels('preset', strict)
      const present = new Set([...sources.map((s) => s.id), ...sinks.map((s) => s.id)])
      for (const rule of strict.sources ?? []) {
        if (isRuleRef(rule) || rule.enabled === false || present.has(`preset:${rule.id}`)) continue
        sources.push(compileSource('preset', rule))
      }
      for (const rule of strict.sinks ?? []) {
        if (isRuleRef(rule) || rule.enabled === false || present.has(`preset:${rule.id}`)) continue
        sinks.push(compileSink('preset', rule, mode))
      }
    }
  }

  for (const { layer, path } of ordered) {
    statuses.set(layer, { layer, path, status: 'loaded', rules: counts.get(layer) ?? 0 })
  }

  return {
    policy: {
      mode,
      resetOnClear,
      subagents: 'shared',
      userDeclassify,
      userDeclassifyFrom: declassifier?.layer ?? 'default',
      onUnknownHistory,
      labels,
      sources,
      sinks,
    },
    lockdown,
    layers: STATUS_ORDER.flatMap((name) => {
      const status = statuses.get(name)
      return status === undefined ? [] : [status]
    }),
    warnings,
  }
}

/** Every declared label name, sorted. */
export function allLabels(policy: CompiledPolicy): string[] {
  return Object.keys(policy.labels).sort()
}

/** Whether the sink's label condition holds for this taint set. */
export function isSinkActive(sink: CompiledSink, labels: ReadonlySet<string>): boolean {
  const { anyOf, allOf } = sink.when
  if (anyOf.length > 0 && !anyOf.some((label) => labels.has(label))) return false
  return allOf.every((label) => labels.has(label))
}

const TRUST_RANK: readonly LayerName[] = ['managed', 'user', 'preset', 'project']

function decision(matches: SinkMatch[]): SinkDecision {
  matches.sort(
    (a, b) =>
      ACTION_ORDER.indexOf(b.action) - ACTION_ORDER.indexOf(a.action) ||
      TRUST_RANK.indexOf(a.sink.layer) - TRUST_RANK.indexOf(b.sink.layer),
  )
  const primary = matches[0]
  return primary === undefined ? { action: 'allow', matches } : { action: primary.action, matches, primary }
}

/** Judges one call against the active sinks: the strictest matching action, or allow. */
export function evaluateSinks(policy: CompiledPolicy, call: ToolCall, labels: ReadonlySet<string>): SinkDecision {
  const matches: SinkMatch[] = []
  for (const sink of policy.sinks) {
    if (isSinkActive(sink, labels) && sink.test(call)) matches.push({ sink, action: sink.action })
  }
  return decision(matches)
}

/** The enabled sources with this timing that fire on the call. */
export function matchSources(policy: CompiledPolicy, call: ToolCall, timing: Timing): CompiledSource[] {
  const fired: CompiledSource[] = []
  for (const source of policy.sources) {
    if (source.on === timing && source.test(call)) fired.push(source)
  }
  return fired
}

function failSafeMatches(sink: CompiledSink, tool: string): boolean {
  const parts = sinkParts.get(sink)
  if (parts === undefined) return true
  if (sink.trusted) return parts.block.some((m) => m.matchesName(tool))
  if (parts.block.some((m) => m.kind === 'regex')) return true
  return parts.block.some((m) => m.matchesName(tool))
}

/** Minimal deny-on-doubt check for the guard's catch handler; never runs a project regex. */
export function failSafeDecision(policy: CompiledPolicy, call: ToolCall, labels: ReadonlySet<string>): SinkDecision {
  const matches: SinkMatch[] = []
  for (const sink of policy.sinks) {
    if (sink.action === 'audit' || !isSinkActive(sink, labels)) continue
    if (failSafeMatches(sink, call.tool)) matches.push({ sink, action: 'deny' })
  }
  return decision(matches)
}

/** Which tools are refused or need approval under this taint set. */
export function activeSummary(policy: CompiledPolicy, labels: ReadonlySet<string>, inventory: readonly string[]): ActiveSummary {
  const active = policy.sinks.filter((sink) => sink.action !== 'audit' && isSinkActive(sink, labels))
  const names = [...new Set([...inventory, ...policy.sinks.flatMap((sink) => sink.names)])]
  const denied: string[] = []
  const asked: string[] = []
  for (const name of names) {
    const actions = active.filter((sink) => sink.testTool(name) !== 'no').map((sink) => sink.action)
    if (actions.includes('deny')) denied.push(name)
    else if (actions.includes('ask')) asked.push(name)
  }
  const deniedPatterns = new Set<string>()
  const askedPatterns = new Set<string>()
  for (const sink of active) {
    const parts = sinkParts.get(sink)
    const matchers = parts?.block ?? []
    for (const matcher of matchers) {
      if (matcher.patterns.length === 0 || names.some((name) => matcher.matchesName(name))) continue
      const target = sink.action === 'deny' ? deniedPatterns : askedPatterns
      for (const pattern of matcher.patterns) target.add(pattern)
    }
  }
  return {
    denied: denied.sort(),
    asked: asked.sort(),
    deniedPatterns: [...deniedPatterns],
    askedPatterns: [...askedPatterns].filter((pattern) => !deniedPatterns.has(pattern)),
  }
}
