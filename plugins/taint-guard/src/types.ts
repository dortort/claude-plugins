// Shared types of the pure modules under src/, which never touch `$`.

export type JsonValue = null | boolean | number | string | JsonValue[] | { [key: string]: JsonValue }

export type LayerName = 'preset' | 'managed' | 'user' | 'project'
export type Mode = 'enforce' | 'ask' | 'audit'
export type Action = 'deny' | 'ask' | 'audit'
export type Timing = 'attempt' | 'success'
export type Declassify = 'allow' | 'confirm' | 'never'
export type UnknownHistory = 'assume-tainted' | 'ignore'
export type PresetName = 'strict' | 'trifecta' | 'none'

/** Strictness orders, least strict first. */
export const MODE_ORDER: readonly Mode[] = ['audit', 'ask', 'enforce']
export const DECLASSIFY_ORDER: readonly Declassify[] = ['allow', 'confirm', 'never']
export const UNKNOWN_HISTORY_ORDER: readonly UnknownHistory[] = ['ignore', 'assume-tainted']
export const PRESET_ORDER: readonly PresetName[] = ['none', 'trifecta', 'strict']
export const ACTION_ORDER: readonly Action[] = ['audit', 'ask', 'deny']

// ---------------------------------------------------------------------------
// The policy file, as JSON holds it (schema/taint-guard.schema.json).
// ---------------------------------------------------------------------------

/** Exactly one of `exact`, `prefix`, `regex`, `anyOf`; `flags: "i"` only with `prefix` or `regex`. */
export type ToolSelector =
  | { exact: string }
  | { prefix: string; flags?: 'i' }
  | { regex: string; flags?: 'i' }
  | { anyOf: string[] }

/** One argument by JSON Pointer; `matches` needs the value present, `notMatches` holds when it is absent. */
export type ArgumentPredicate = { pointer: string; flags?: 'i' } & (
  | { equals: JsonValue }
  | { matches: string }
  | { notMatches: string }
  | { exists: boolean }
)

/** A tool selector plus optional argument predicates; all must hold. */
export type Matcher = { tool: ToolSelector; arguments?: ArgumentPredicate[] }

export type SourceRule = {
  id: string
  description?: string
  match: Matcher
  /** Default `attempt`. */
  on?: Timing
  /** Label names, at least one. */
  taints: string[]
  /** Default true. */
  enabled?: boolean
}

export type SinkRule = {
  id: string
  description?: string
  /** `anyOf` and/or `allOf` label names; both present = both hold; `{}` = always active. */
  when: { anyOf?: string[]; allOf?: string[] }
  /** At least one matcher. */
  block: Matcher[]
  except?: Matcher[]
  /** Default `deny`. */
  action?: Action
  /** At most 1,000 characters. */
  reason?: string
  enabled?: boolean
}

/** Switches off a rule by its namespaced id, when the referring layer may disable that layer's rules. */
export type RuleRef = { id: string; enabled: false }

export type PolicyFile = {
  $schema?: string
  version: 1
  description?: string
  mode?: Mode
  subagents?: 'shared'
  resetOnClear?: boolean
  userDeclassify?: Declassify
  onUnknownHistory?: UnknownHistory
  /** At least one label. Names: letters, digits, `-`, 1–32 characters. */
  labels: Record<string, { description?: string }>
  sources?: Array<SourceRule | RuleRef>
  sinks?: Array<SinkRule | RuleRef>
}

export type ValidationResult = { ok: true; policy: PolicyFile } | { ok: false; errors: string[] }

// ---------------------------------------------------------------------------
// Loading: four layers in, one compiled policy out.
// ---------------------------------------------------------------------------

/** A policy file as read from disk: `text` null when the file does not exist. */
export type LayerText = {
  layer: Exclude<LayerName, 'preset'>
  path: string
  text: string | null
  /** Set when the file exists but could not be read. */
  readError?: string
}

export type LoadInput = {
  /** The effective preset (the stricter of the user's option and the managed floor). */
  preset: PresetName
  /** True when managed policy set a preset floor: the preset layer then counts as managed for disabling. */
  presetFromManaged: boolean
  managed: LayerText | null
  user: LayerText | null
  project: LayerText | null
  /** Set when `$.settings.read({ source: "policy" })` threw: lockdown. */
  managedReadError?: string
  /** Extra warnings to carry (for example a user-set managedPolicyPath that was ignored). */
  warnings?: string[]
}

export type LayerStatus = {
  layer: LayerName
  path: string | null
  status: 'loaded' | 'absent' | 'invalid' | 'dropped'
  rules: number
  error?: string
}

/** A tool call as the evaluator sees it. */
export type ToolCall = {
  tool: string
  /** The call's arguments: the event's fields less `tool`, `tool_use_id`, `agentId`, `consent`. */
  args: Readonly<Record<string, unknown>>
  agentId?: string
  toolUseId?: string
}

/** Whether a selector matches a tool name, ignoring argument predicates. */
export type ToolMatch = 'yes' | 'maybe' | 'no'

export type CompiledSource = {
  /** Namespaced: `<layer>:<id>`. */
  id: string
  layer: LayerName
  on: Timing
  taints: readonly string[]
  description?: string
  /** True for preset, managed and user rules; false for project rules. */
  trusted: boolean
  /** Tool selector and argument predicates both hold. */
  test: (call: ToolCall) => boolean
  /** The tool selector alone: `yes` with no argument predicates, `maybe` with some, `no` otherwise. */
  testTool: (tool: string) => ToolMatch
}

export type CompiledSink = {
  id: string
  layer: LayerName
  when: { anyOf: readonly string[]; allOf: readonly string[] }
  /** The action as written (default `deny`). */
  declared: Action
  /** The action after the policy's `mode` (ask turns deny into ask; audit turns every action into audit). */
  action: Action
  reason: string
  description?: string
  trusted: boolean
  /** Some block matcher matches and no except matcher does. */
  test: (call: ToolCall) => boolean
  /** By tool name alone: `yes` when a block matcher with no argument predicates matches and no except matcher could; `maybe` when argument predicates decide; `no` otherwise. */
  testTool: (tool: string) => ToolMatch
  /** The exact tool names its block selectors name (`exact`, `anyOf`), for listing. */
  names: readonly string[]
  /** Human-readable text of its non-exact block selectors (`/^mcp__.+__send/i`, `mcp__slack…`). */
  patterns: readonly string[]
}

export type CompiledPolicy = {
  mode: Mode
  resetOnClear: boolean
  subagents: 'shared'
  userDeclassify: Declassify
  /** Which layer set the effective userDeclassify (`default` when none did). */
  userDeclassifyFrom: LayerName | 'default'
  onUnknownHistory: UnknownHistory
  /** Every declared label, with the first description found (managed, user, project, preset order). */
  labels: Readonly<Record<string, { description?: string; layer: LayerName }>>
  /** Enabled sources, in layer order managed, user, project, preset. */
  sources: readonly CompiledSource[]
  /** Enabled sinks, in the same order. */
  sinks: readonly CompiledSink[]
}

export type LoadedPolicy = {
  policy: CompiledPolicy
  /** Why every sink is active, or null. */
  lockdown: string | null
  layers: LayerStatus[]
  warnings: string[]
}

// ---------------------------------------------------------------------------
// Evaluation.
// ---------------------------------------------------------------------------

export type SinkMatch = { sink: CompiledSink; action: Action }

/** The strictest matching active sink's action (deny > ask > audit), or allow; matches are strictest first. */
export type SinkDecision = {
  action: 'allow' | Action
  matches: SinkMatch[]
  primary?: SinkMatch
}

/** What is refused or asked right now, for the band and the context lines. */
export type ActiveSummary = {
  /** Concrete tool names refused (deny) now: from sink names and the inventory. Sorted. */
  denied: string[]
  /** Concrete tool names that need approval (ask) now, not also denied. Sorted. */
  asked: string[]
  /** Patterns of active deny sinks that matched no listed name. */
  deniedPatterns: string[]
  /** Patterns of active ask sinks that matched no listed name. */
  askedPatterns: string[]
}

// ---------------------------------------------------------------------------
// Taint state (src/state.ts) and the conversation it is rebuilt from.
// ---------------------------------------------------------------------------

export type Firing = {
  rule: string
  tool: string
  labels: string[]
  at: number
  agentId?: string
  toolUseId?: string
}

export type TaintSnapshot = {
  labels: string[]
  firedBy: Firing[]
  blockedCount: number
}

/** `$.store` copy under `taint:<sessionId>`. */
export type StoredTaint = {
  labels: string[]
  firedBy: Firing[]
  savedAt: number
  /** The last tool_use_id a user declassification covered: a rebuild replays only the history after it. */
  clearedThrough?: string
}

/** The parts of `SessionMessage` the rebuild reads (`$.session.messages()`). */
export type MessageLike = {
  role: 'user' | 'assistant'
  text: string
  toolUses: ReadonlyArray<{
    tool_use_id: string
    tool: string
    input: Readonly<Record<string, unknown>>
    text?: string
    isError?: true
    agentId?: string
  }>
  toolResults?: ReadonlyArray<{ tool_use_id: string; text: string; isError: boolean }>
}

// ---------------------------------------------------------------------------
// Audit log (src/audit.ts).
// ---------------------------------------------------------------------------

export type AuditEvent =
  | 'taint'
  | 'deny'
  | 'ask-allowed'
  | 'ask-refused'
  | 'audit-match'
  | 'declassify'
  | 'reset'
  | 'rebuild'
  | 'lockdown'
  | 'guard-failure'
  | 'background-before-taint'
  | 'compact'
  | 'disabled'
  | 'reload'

export type AuditEntry = {
  /** ISO 8601. */
  ts: string
  event: AuditEvent
  tool?: string
  toolUseId?: string
  agentId?: string
  rule?: string
  labels?: string[]
  /** HMAC-SHA-256 of the canonical JSON arguments, hex. */
  argsHmac?: string
  /** First 200 characters of the canonical JSON arguments, only with auditArguments. */
  args?: string
  /** Free text: the reason, the record that rebuilt taint, the lockdown error. */
  detail?: string
}

/** The file system the audit log writes through (`$.fs` in the module, memory in tests). */
export type AuditFs = {
  /** The file's text, or null when it does not exist. */
  read: (path: string) => Promise<string | null>
  /** Replaces the file's whole content, creating directories. */
  write: (path: string, text: string) => Promise<void>
}
