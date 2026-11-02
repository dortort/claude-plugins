import type { Matcher, PolicyFile, PresetName } from './types.ts'

export type ServerFamily = 'mail' | 'docs' | 'chat' | 'web'
export type ToolVerb = 'read' | 'write' | 'both' | 'other'

export type ToolClass = {
  mcp: boolean
  server: string | null
  family: ServerFamily | null
  /** Every family whose token the server name contains, in mail, docs, chat, web order; `family` is the first. */
  families: readonly ServerFamily[]
  verb: ToolVerb | null
}

export const SCHEMA_ID =
  'https://raw.githubusercontent.com/dortort/claude-plugins/main/plugins/taint-guard/schema/taint-guard.schema.json'

export const FAMILY_TOKENS: Record<ServerFamily, readonly string[]> = {
  mail: ['gmail', 'google_mail', 'google-mail', 'googlemail', 'outlook', 'mail'],
  docs: ['drive', 'gdrive', 'google_drive', 'google-drive', 'docs', 'google_docs', 'notion', 'onedrive', 'sharepoint'],
  chat: ['slack', 'teams', 'chat'],
  web: ['fetch', 'browser', 'chrome', 'puppeteer', 'playwright', 'selenium', 'crawl', 'scrape', 'tavily', 'brave', 'web'],
}

export const READ_VERBS: readonly string[] = ['get', 'read', 'search', 'list', 'fetch', 'download', 'history']
export const WRITE_VERBS: readonly string[] = [
  'send',
  'post',
  'reply',
  'forward',
  'create',
  'update',
  'upload',
  'share',
  'schedule',
  'comment',
  'invite',
]

const PRIVATE_FAMILIES: readonly ServerFamily[] = ['mail', 'docs', 'chat']
const FAMILIES: readonly ServerFamily[] = [...PRIVATE_FAMILIES, 'web']
const MCP_PREFIX = 'mcp__'

function hasVerb(segment: string, verbs: readonly string[]): boolean {
  const lower = segment.toLowerCase()
  return verbs.some((verb) => {
    for (let at = lower.indexOf(verb); at !== -1; at = lower.indexOf(verb, at + 1)) {
      const before = lower[at - 1]
      if (at === 0 || before === '_' || before === '-') return true
    }
    return false
  })
}

/** Classifies a tool name by MCP server family and verb, as the presets' regexes do. */
export function classifyTool(tool: string): ToolClass {
  const end = tool.slice(0, MCP_PREFIX.length).toLowerCase() === MCP_PREFIX ? tool.indexOf('__', MCP_PREFIX.length) : -1
  if (end === -1) return { mcp: false, server: null, family: null, families: [], verb: null }
  const server = tool.slice(MCP_PREFIX.length, end)
  const segment = tool.slice(end + 2)
  const lowerServer = server.toLowerCase()
  const families = FAMILIES.filter((name) => FAMILY_TOKENS[name].some((token) => lowerServer.includes(token)))
  const read = hasVerb(segment, READ_VERBS)
  const write = hasVerb(segment, WRITE_VERBS)
  const verb: ToolVerb = read && write ? 'both' : read ? 'read' : write ? 'write' : 'other'
  return { mcp: true, server, family: families[0] ?? null, families, verb }
}

const escape = (text: string): string => text.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
const alternation = (words: readonly string[]): string => `(?:${words.map(escape).join('|')})`

const SERVER_CHAR = '(?:[^_]|_(?!_))'
const VERB_AT = '(?:[\\s\\S]*[_-])?'
const PRIVATE_TOKENS = alternation(PRIVATE_FAMILIES.flatMap((name) => FAMILY_TOKENS[name]))
const MAIL_TOKENS = alternation(FAMILY_TOKENS.mail)
const WEB_TOKENS = alternation(FAMILY_TOKENS.web)
const READ = alternation(READ_VERBS)
const WRITE = alternation(WRITE_VERBS)

const onServerWith = (tokens: string, toolSegment: string): string =>
  `^mcp__(?=${SERVER_CHAR}*__${toolSegment})${SERVER_CHAR}*?${tokens}`

/** An MCP tool on a mail, documents or chat server whose tool segment has a read verb. */
export const PRIVATE_READ_REGEX = onServerWith(PRIVATE_TOKENS, `${VERB_AT}${READ}`)
/** An MCP tool on a mail, documents or chat server whose tool segment has neither a read nor a write verb. */
export const PRIVATE_OTHER_REGEX = onServerWith(PRIVATE_TOKENS, `(?!${VERB_AT}(?:${READ}|${WRITE}))`)
/** An MCP tool on any server whose tool segment has a write verb. */
export const MCP_WRITE_REGEX = `^mcp__${SERVER_CHAR}*__${VERB_AT}${WRITE}`
/** Any MCP tool on a web, browser or fetch server, which both reads third-party pages and reaches URLs Claude chooses. */
export const WEB_TOOL_REGEX = onServerWith(WEB_TOKENS, '')
/** A mail-family MCP tool whose tool segment ends in create_draft. */
export const MAIL_CREATE_DRAFT_REGEX = onServerWith(MAIL_TOKENS, `${VERB_AT}create_draft$`)
/** A path or glob naming a secret file: .env files, SSH keys, credentials, keys, certificates and CLI login stores. */
export const SECRET_FILE_REGEX =
  '(^|[\\\\/])(?:\\.env(?!\\.(?:example|sample|template|dist)$)[^\\\\/]*|id_(?:rsa|dsa|ecdsa|ed25519)|credentials|\\.git-credentials|\\.netrc|\\.pgpass|\\.npmrc|[^\\\\/]*\\.pem|[^\\\\/]*\\.key|gh[\\\\/]hosts\\.yml|\\.docker[\\\\/]config\\.json|\\.kube[\\\\/]config)$'

const PATTERN_WORDS: ReadonlyMap<string, string> = new Map([
  [`/${MCP_WRITE_REGEX}/i`, `MCP tools that ${WRITE_VERBS.slice(0, -1).join(', ')} or ${WRITE_VERBS.at(-1)}`],
  [`/${PRIVATE_OTHER_REGEX}/i`, 'other tools on mail, documents or chat MCP servers'],
  [`/${PRIVATE_READ_REGEX}/i`, 'read tools on mail, documents or chat MCP servers'],
  [`/${MAIL_CREATE_DRAFT_REGEX}/i`, 'mail draft tools'],
  [`/${WEB_TOOL_REGEX}/i`, 'every tool on web, browser or fetch MCP servers'],
])

/** Plain words for a preset's tool pattern; any other pattern is returned unchanged. */
export function describePattern(pattern: string): string {
  return PATTERN_WORDS.get(pattern) ?? pattern
}

const LABELS: PolicyFile['labels'] = {
  private: { description: 'Data the user owns: mail, documents, chats' },
  untrusted: { description: 'Text written by third parties' },
  secret: { description: 'Credentials and keys' },
}

const SOURCES: NonNullable<PolicyFile['sources']> = [
  {
    id: 'private-read',
    description: 'A read verb on a mail, documents or chat MCP server',
    match: { tool: { regex: PRIVATE_READ_REGEX, flags: 'i' } },
    on: 'attempt',
    taints: ['private', 'untrusted'],
  },
  {
    id: 'private-other',
    description: 'A tool with neither a read nor a write verb on a mail, documents or chat MCP server',
    match: { tool: { regex: PRIVATE_OTHER_REGEX, flags: 'i' } },
    on: 'attempt',
    taints: ['private', 'untrusted'],
  },
  {
    id: 'web-content',
    description: 'Web pages and search results',
    match: { tool: { anyOf: ['WebFetch', 'WebSearch'] } },
    on: 'success',
    taints: ['untrusted'],
  },
  {
    id: 'web-mcp',
    description: 'Any tool on a web, browser or fetch MCP server',
    match: { tool: { regex: WEB_TOOL_REGEX, flags: 'i' } },
    on: 'success',
    taints: ['untrusted'],
  },
  {
    id: 'secret-files',
    description: 'Reading a secret file',
    match: { tool: { exact: 'Read' }, arguments: [{ pointer: '/file_path', matches: SECRET_FILE_REGEX, flags: 'i' }] },
    on: 'attempt',
    taints: ['secret'],
  },
  {
    id: 'secret-grep',
    description: 'Searching a secret file',
    match: { tool: { exact: 'Grep' }, arguments: [{ pointer: '/path', matches: SECRET_FILE_REGEX, flags: 'i' }] },
    on: 'attempt',
    taints: ['secret'],
  },
  {
    id: 'secret-grep-glob',
    description: 'Searching files whose glob names a secret file',
    match: { tool: { exact: 'Grep' }, arguments: [{ pointer: '/glob', matches: SECRET_FILE_REGEX, flags: 'i' }] },
    on: 'attempt',
    taints: ['secret'],
  },
]

const OUTBOUND: Matcher[] = [
  { tool: { exact: 'Bash' } },
  { tool: { exact: 'WebFetch' } },
  { tool: { regex: MCP_WRITE_REGEX, flags: 'i' } },
  { tool: { regex: PRIVATE_OTHER_REGEX, flags: 'i' } },
  { tool: { regex: WEB_TOOL_REGEX, flags: 'i' } },
]

const base = (description: string): Omit<PolicyFile, 'sinks'> => ({
  version: 1,
  description,
  labels: LABELS,
  sources: SOURCES,
})

const TRIFECTA: PolicyFile = {
  ...base('Ask before outbound calls once private and untrusted content meet; refuse them once secrets are read'),
  sinks: [
    {
      id: 'outbound-secret',
      description: 'Outbound tools after reading secrets',
      when: { anyOf: ['secret'] },
      block: [...OUTBOUND, { tool: { exact: 'WebSearch' } }],
      action: 'deny',
      reason: 'This tool can send data out of the session, and the session has read secrets.',
    },
    {
      id: 'outbound-private',
      description: 'Outbound tools once private and untrusted content are both present',
      when: { allOf: ['private', 'untrusted'] },
      block: OUTBOUND,
      except: [{ tool: { regex: MAIL_CREATE_DRAFT_REGEX, flags: 'i' } }],
      action: 'ask',
      reason: 'This would send data out of a session that holds private, third-party content.',
    },
  ],
}

const STRICT: PolicyFile = {
  ...base('Refuse every outbound or file-changing tool once any label is present'),
  sinks: [
    {
      id: 'outbound-any',
      description: 'Outbound and file-changing tools once any label is present',
      when: { anyOf: ['private', 'untrusted', 'secret'] },
      block: [...OUTBOUND, { tool: { anyOf: ['WebSearch', 'Write', 'Edit', 'NotebookEdit'] } }],
      action: 'deny',
      reason: 'This tool can send data out or change files, and the session holds private, untrusted or secret content.',
    },
  ],
}

export const PRESETS: Record<PresetName, PolicyFile | null> = {
  strict: STRICT,
  trifecta: TRIFECTA,
  none: null,
}
