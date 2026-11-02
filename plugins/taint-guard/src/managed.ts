import type { PresetName } from './types.ts'
import { PRESET_ORDER } from './types.ts'

export type ManagedOptions = { enabled?: boolean; preset?: PresetName; managedPolicyPath?: string }

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
}

function isPreset(value: unknown): value is PresetName {
  return typeof value === 'string' && (PRESET_ORDER as readonly string[]).includes(value)
}

function stricter(a: PresetName | undefined, b: PresetName): PresetName {
  return a === undefined || PRESET_ORDER.indexOf(b) > PRESET_ORDER.indexOf(a) ? b : a
}

/** The security-relevant options managed settings set for this plugin. */
export function managedOptionsFrom(settings: unknown, pluginName: string): ManagedOptions {
  const result: ManagedOptions = {}
  if (!isObject(settings) || !isObject(settings.pluginConfigs)) return result
  const configs = settings.pluginConfigs
  const keys = Object.keys(configs)
    .filter((key) => key === pluginName || key.startsWith(`${pluginName}@`))
    .sort()
  for (const key of keys) {
    const entry = configs[key]
    const options = isObject(entry) ? entry.options : undefined
    if (!isObject(options)) continue
    if (options.enabled === true) result.enabled = true
    if (isPreset(options.preset)) result.preset = stricter(result.preset, options.preset)
    const path = options.managedPolicyPath
    if (result.managedPolicyPath === undefined && typeof path === 'string' && path !== '') {
      result.managedPolicyPath = path
    }
  }
  return result
}

/** The stricter of the user's preset option and the managed floor. */
export function effectivePreset(userPreset: unknown, managed: ManagedOptions): { preset: PresetName; fromManaged: boolean } {
  const user: PresetName = isPreset(userPreset) ? userPreset : 'trifecta'
  return {
    preset: managed.preset === undefined ? user : stricter(user, managed.preset),
    fromManaged: managed.preset !== undefined,
  }
}

/** Expands a leading ~ to the home directory. */
export function expandHome(path: string, home: string | undefined): string {
  if (home === undefined || home === '') return path
  if (path === '~') return home
  if (path.startsWith('~/') || path.startsWith('~\\')) return home.replace(/[\\/]+$/, '') + path.slice(1)
  return path
}

/** The warning for a managedPolicyPath set outside managed settings, or null. */
export function ignoredManagedPathWarning(userValue: unknown, managed: ManagedOptions): string | null {
  if (typeof userValue !== 'string' || userValue === '' || userValue === managed.managedPolicyPath) return null
  return 'managedPolicyPath in user settings is ignored; only managed settings can set it'
}
