import { mock } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { AuditEntry } from '../src/types.ts'
import type { On, PromptOrigin, RenderElement, SessionCompactResult, SessionMessage, ToolCallResult } from 'claude-code'

declare function setTimeout(fn: () => void, ms: number): unknown

export const CWD = '/work'
export const HOME = '/home/tester'
export const SESSION_ID = 'sess-1'
export const T0 = 1_793_000_000_000
export const USER_POLICY = `${HOME}/.claude/taint-guard.json`
export const PROJECT_POLICY = `${CWD}/.claude/taint-guard.json`
export const MANAGED_POLICY = '/etc/claude-code/taint-guard.json'
export const SURFACES = ['terminal', 'desktop'] as const

export const auditFile = (id: string = SESSION_ID): string => `${HOME}/.claude/taint-guard/audit/${id}.jsonl`

export const BY_PERSON = { origin: { kind: 'composer' } as PromptOrigin, presentation: { isFullscreen: false, columns: 100 } }
export const BY_SDK = { origin: { kind: 'sdk' } as PromptOrigin, presentation: { isFullscreen: false, columns: 100 } }

export const BAND = {
  plugin: 'taint-guard',
  component: 'AbovePrompt',
  requestId: 'above-prompt',
  props: {
    hasSurvey: false,
    isWorking: false,
    maxRows: 10,
    bodyColumns: 100,
    scroll: { offset: 0, bodyRows: 10 },
    view: {},
  },
} as const

export const GMAIL_READ = 'mcp__gmail__read_message'

/** The spec's example policy: Bash denied after private mail or secrets, outbound asks after private and untrusted. */
export const EXAMPLE_POLICY = {
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
    { id: 'web-content', match: { tool: { anyOf: ['WebFetch', 'WebSearch'] } }, on: 'success', taints: ['untrusted'] },
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

export type ToolAnswer = ToolCallResult | ((e: Readonly<Record<string, unknown>>) => ToolCallResult)

export type KitOptions = {
  files?: Record<string, string>
  managed?: Record<string, unknown> | Error
  messages?: SessionMessage[]
  agents?: Record<string, SessionMessage[]>
  store?: Record<string, unknown>
  /** `$.ui.ask` answers in order; `null`, or running out, dismisses; a function answers once it settles. */
  answers?: Answer[]
  tools?: Record<string, ToolAnswer>
  compact?: SessionCompactResult
  env?: Record<string, string>
}

export type Answer = string | null | (() => Promise<string | null>)

type Wait = { due: number; resolve: () => void }
type Asked = { question: string; options: string[]; header: string }
type Ran = { tool: string; args: Record<string, unknown> }
type Compacted = { instructions: string | undefined; messages: readonly SessionMessage[] }

export type Kit = ReturnType<typeof engine>

export function engine(on: On, options: KitOptions = {}) {
  let now = T0
  const waits: Wait[] = []
  const faults = { clock: false }
  let gate: Promise<void> | null = null
  const files = new Map<string, string>(Object.entries(options.files ?? {}))
  const store = new Map<string, unknown>(Object.entries(options.store ?? {}))
  const answers = [...(options.answers ?? [])]
  const tools: Record<string, ToolAnswer> = { ...(options.tools ?? {}) }
  const logs: string[] = []
  const debug: string[] = []
  const asked: Asked[] = []
  const ran: Ran[] = []
  const commands: string[] = []
  const submitted: Array<{ text: string; context: readonly string[] | undefined }> = []
  const compacted: Compacted[] = []
  let sessionId = SESSION_ID
  let messages: SessionMessage[] = [...(options.messages ?? [])]
  const agents: Record<string, SessionMessage[]> = { ...(options.agents ?? {}) }
  let compactAnswer = options.compact

  mock.env(on, { HOME, ...(options.env ?? {}) })

  on('clock.now', () => {
    if (faults.clock) return { deny: 'the clock is unavailable' }
    return { value: now }
  })
  const hold = (_$: unknown, e: { ms: number }) =>
    new Promise<{ value: undefined }>((resolve) => {
      waits.push({ due: now + e.ms, resolve: () => resolve({ value: undefined }) })
    })
  on('clock.every', hold)
  on('clock.after', hold)
  on('clock.sleep', hold)

  on('store.get', (_$, e) => ({ value: store.get(e.key) }))
  on('store.set', (_$, e) => {
    store.set(e.key, JSON.parse(JSON.stringify(e.value)))
    return { value: undefined }
  })
  on('store.delete', (_$, e) => {
    store.delete(e.key)
    return { value: undefined }
  })
  on('store.keys', () => ({ value: [...store.keys()] }))

  on('fs.exists', (_$, e) => ({ value: files.has(e.path) }))
  on('fs.read', (_$, e) => {
    const text = files.get(e.path)
    if (text === undefined) return { deny: `ENOENT: no such file, ${e.path}` }
    return { value: text }
  })
  on('fs.write', (_$, e) => {
    files.set(e.path, e.text)
    return { value: undefined }
  })

  on('settings.read', (_$, e) => {
    if (e.source !== 'policy') return { value: {} }
    if (options.managed instanceof Error) return { deny: options.managed.message }
    return { value: options.managed ?? {} }
  })

  on('session.id', () => ({ value: sessionId }))
  on('session.cwd', () => ({ value: CWD }))
  on('session.messages', async (_$, e) => {
    if (e.agentId === undefined) {
      const held = gate
      const seen = messages
      gate = null
      if (held !== null) await held
      return { value: seen }
    }
    const found = agents[e.agentId]
    return { value: found ?? { deny: `no agent ${e.agentId}` } }
  })
  on('command.register', (_$, e) => {
    commands.push(e.name)
    return { value: { command: e.name } }
  })
  on('ui.log', (_$, e) => {
    if (e.to === 'debug') debug.push(e.text)
    else logs.push(e.text)
    return { value: undefined }
  })

  on('tool.call', async (_$, e) => {
    const input = e as unknown as Readonly<Record<string, unknown>>
    if (e.tool === 'AskUserQuestion') {
      const q = (input.questions as Array<{ question: string; header: string; options: Array<{ label: string }> }>)[0]
      const question = q?.question ?? ''
      asked.push({ question, header: q?.header ?? '', options: (q?.options ?? []).map((o) => o.label) })
      const next = answers.shift()
      const answer = typeof next === 'function' ? await next() : next
      if (answer === undefined || answer === null) return { deny: 'dismissed' }
      return { result: { questions: input.questions, answers: { [question]: answer } } } as ToolCallResult
    }
    const { tool, tool_use_id: id, ...args } = input as { tool: string; tool_use_id: string } & Record<string, unknown>
    ran.push({ tool, args })
    const answer = tools[tool]
    const result: ToolCallResult =
      answer === undefined
        ? ({ result: `${tool} ran`, text: `${tool} ran` } as ToolCallResult)
        : typeof answer === 'function'
          ? answer(input)
          : answer
    const failed = result.deny !== undefined || result.isError === true
    const text = result.deny ?? result.text ?? String(result.result)
    messages = [...messages, use(tool, args, { id, text, ...(failed ? { isError: true as const } : {}) })]
    return result
  })

  on('session.start', (_$, e) => ({ cwd: e.cwd }))
  on('session.end', (_$, e) => ({ sessionId: e.sessionId }))
  on('session.compact', (_$, e) => {
    compacted.push({ instructions: e.instructions, messages: e.messages })
    return compactAnswer ?? { messages: [{ role: 'assistant', text: 'Summary of the conversation so far.', toolUses: [] }] }
  })
  on('classic.SessionStart', (_$, e) => {
    if (e.source === 'clear') messages = []
    return {}
  })
  on('classic.Stop', () => ({}))
  on('prompt.submit', (_$, e) => {
    submitted.push({ text: e.text, context: e.context })
    return { text: e.text, context: e.context, origin: e.origin }
  })
  on('turn.start', (_$, e) => ({ turnId: e.turnId }))
  on('turn.complete', () => ({ text: '' }))
  on('tool.describe', (_$, e) => ({ description: e.description }))
  on('ui.render', ($, e) => {
    const { Text } = $.ui.resolve(e)
    return h(Text, null, 'engine band') as RenderElement
  })

  const settle = async (rounds = 20): Promise<void> => {
    for (let i = 0; i < rounds; i += 1) await new Promise<void>((resolve) => setTimeout(() => resolve(), 0))
  }

  const kit = {
    files,
    store,
    tools,
    logs,
    debug,
    asked,
    ran,
    commands,
    submitted,
    compacted,
    faults,
    settle,

    now: (): number => now,

    async advance(ms: number): Promise<void> {
      const target = now + ms
      for (;;) {
        waits.sort((a, b) => a.due - b.due)
        const first = waits[0]
        if (first === undefined || first.due > target) break
        waits.shift()
        now = Math.max(now, first.due)
        first.resolve()
        await settle()
      }
      now = target
      await settle()
    },

    setSession(id: string): void {
      sessionId = id
    },

    messages: (): SessionMessage[] => messages,

    setMessages(next: SessionMessage[]): void {
      messages = next
    },

    setAgent(id: string, next: SessionMessage[]): void {
      agents[id] = next
    },

    answer(...next: Answer[]): void {
      answers.push(...next)
    },

    /** Holds the next main `$.session.messages()` until the returned function runs; it answers with the history as it stood when called. */
    holdMessages(): () => void {
      let release = (): void => undefined
      gate = new Promise<void>((resolve) => {
        release = resolve
      })
      return release
    },

    setCompact(next: SessionCompactResult | undefined): void {
      compactAnswer = next
    },

    async audit(id: string = SESSION_ID): Promise<AuditEntry[]> {
      await kit.advance(1000)
      const text = files.get(auditFile(id)) ?? ''
      return text
        .split('\n')
        .filter((line) => line !== '')
        .map((line) => JSON.parse(line) as AuditEntry)
    },
  }
  return kit
}

export async function start($: Engine, kit: Kit, isInteractive = true): Promise<void> {
  await $.session.start({ cwd: CWD, surface: isInteractive ? 'terminal' : null, isInteractive })
  await kit.settle()
}

export function call(
  $: Engine,
  tool: string,
  args: Record<string, unknown> = {},
  agentId?: string,
): Promise<ToolCallResult> {
  const input = { tool, ...args, ...(agentId === undefined ? {} : { agentId }) }
  return $.tool.call(input as unknown as Parameters<Engine['tool']['call']>[0])
}

export function compact($: Engine, kit: Kit, instructions?: string): Promise<SessionCompactResult> {
  const input = { trigger: 'manual', messages: kit.messages(), ...(instructions === undefined ? {} : { instructions }) }
  return $.session.compact(input as unknown as Parameters<Engine['session']['compact']>[0])
}

export async function submit($: Engine, text: string): Promise<void> {
  await $.prompt.submit({ text, wait: false, origin: { kind: 'composer' } })
}

export async function command($: Engine, args: string, by = BY_PERSON): Promise<string> {
  const { text } = await $.command.run({ command: 'taintguard', args, ...by })
  return text ?? ''
}

/** The labels /taintguard reports; throws on a heading it does not know. */
export async function labels($: Engine): Promise<string[]> {
  const heading = (await command($, '')).split('\n')[0] ?? ''
  if (heading === 'TaintGuard: clean' || heading === 'TaintGuard: off') return []
  const match = /^TaintGuard: tainted \((.*)\)$/.exec(heading)
  if (!match) throw new Error(`unexpected status heading: ${heading}`)
  return (match[1] ?? '').split(', ')
}

let toolUseSeq = 0

export function use(
  tool: string,
  input: Record<string, unknown> = {},
  over: { text?: string; isError?: true; id?: string; agentId?: string } = {},
): SessionMessage {
  toolUseSeq += 1
  const toolUse: SessionMessage['toolUses'][number] = {
    tool_use_id: over.id ?? `toolu_${String(toolUseSeq).padStart(4, '0')}`,
    tool,
    input,
    text: over.text ?? `${tool} ran`,
  }
  if (over.isError) toolUse.isError = true
  if (over.agentId !== undefined) toolUse.agentId = over.agentId
  return { role: 'assistant', text: '', toolUses: [toolUse] }
}

export function said(role: 'user' | 'assistant', text: string): SessionMessage {
  return { role, text, toolUses: [] }
}

export function policyFile(policy: unknown): string {
  return JSON.stringify(policy)
}
