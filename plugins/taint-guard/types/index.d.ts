// TaintGuard's session state: what it keeps in `$.state` under its own name,
// so the taint set survives hot reloads of the hooks module.

/** One source firing: which rule added which labels, from which call. */
export type TaintGuardFiring = {
  /** The namespaced source id (`user:gmail-read`), or `record`, `store`, `history-cut`. */
  rule: string
  tool: string
  labels: string[]
  /** Milliseconds since the epoch. */
  at: number
  agentId?: string
  toolUseId?: string
}

/** The session's taint set. Only grows, except by declassification or a /clear reset. */
export type TaintGuardTaint = {
  labels: string[]
  firedBy: TaintGuardFiring[]
  /** Calls refused (deny, or an ask the user refused) this session. */
  blockedCount: number
}

export type TaintGuardLayerName = 'preset' | 'managed' | 'user' | 'project'

/** One policy layer as the last load saw it. */
export type TaintGuardLayerStatus = {
  layer: TaintGuardLayerName
  path: string | null
  status: 'loaded' | 'absent' | 'invalid' | 'dropped'
  rules: number
  error?: string
}

/** The loaded policy, as the band, /taintguard and the context lines report it. */
export type TaintGuardStatus = {
  enabled: boolean
  preset: 'strict' | 'trifecta' | 'none'
  /** Why every sink is active, or null when the policy loaded cleanly. */
  lockdown: string | null
  layers: TaintGuardLayerStatus[]
  warnings: string[]
  loadedAt: number
}

/** A background task that was already running when the session became tainted. */
export type TaintGuardBackground = {
  id: string
  type: string
  description: string
  command?: string
  notedAt: number
}

declare module 'claude-code' {
  interface PluginState {
    'taint-guard': {
      taint: TaintGuardTaint
      status: TaintGuardStatus | null
      tools: string[]
      background: TaintGuardBackground[]
    }
  }
}
