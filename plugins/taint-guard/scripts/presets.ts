import { readFileSync, writeFileSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import { PRESETS, SCHEMA_ID } from '../src/presets.ts'

export const PRESET_DIR = join(import.meta.dirname, '..', 'presets')

/** The preset files' expected contents, by file name. */
export function renderPresets(): Record<string, string> {
  const files: Record<string, string> = {}
  for (const [name, policy] of Object.entries(PRESETS)) {
    if (policy === null) continue
    files[`${name}.json`] = `${JSON.stringify({ $schema: SCHEMA_ID, ...policy }, null, 2)}\n`
  }
  return files
}

function readOrNull(path: string): string | null {
  try {
    return readFileSync(path, 'utf8')
  } catch {
    return null
  }
}

function main(check: boolean): number {
  const stale: string[] = []
  for (const [file, text] of Object.entries(renderPresets())) {
    const path = join(PRESET_DIR, file)
    if (readOrNull(path) === text) continue
    if (check) stale.push(file)
    else {
      writeFileSync(path, text)
      console.log(`wrote presets/${file}`)
    }
  }
  if (stale.length > 0) {
    console.error(`presets out of date: ${stale.map((file) => `presets/${file}`).join(', ')}; run node scripts/presets.ts`)
    return 1
  }
  return 0
}

if (process.argv[1] === fileURLToPath(import.meta.url)) process.exitCode = main(process.argv.includes('--check'))
