import { existsSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { benignEval } from '../../evals/benign.ts'
import { injectionEval } from '../../evals/injection.ts'
import { percent } from '../../evals/lib/replay.ts'
import { loadPolicy, validatePolicy } from '../../src/policy.ts'
import { FAMILY_TOKENS, PRESETS, SCHEMA_ID } from '../../src/presets.ts'
import { SELF_PROTECT_RULE } from '../../src/protect.ts'

const ROOT = join(import.meta.dirname, '..', '..')
const REPO = join(ROOT, '..', '..')

const read = (...parts: string[]): string => readFileSync(join(...parts), 'utf8')
const readJson = <T>(...parts: string[]): T => JSON.parse(read(...parts)) as T

type UserConfigField = { type: string; default: unknown; options?: string[] }
type Manifest = { name: string; version: string; userConfig: Record<string, UserConfigField> }
type Lock = { version: string; packages: Record<string, { version?: string }> }

const manifest = readJson<Manifest>(ROOT, '.claude-plugin', 'plugin.json')
const pkg = readJson<{ version: string; scripts: Record<string, string> }>(ROOT, 'package.json')
const lock = readJson<Lock>(ROOT, 'package-lock.json')
const readme = read(ROOT, 'README.md')
const deployment = read(ROOT, 'docs', 'deployment.md')
const results = read(ROOT, 'evals', 'RESULTS.md')
const releaseNotes = read(ROOT, 'releases', `${manifest.version}.md`)
const workflowPath = join(REPO, '.github', 'workflows', 'taint-guard.yml')

function section(text: string, heading: string): string {
  const start = text.indexOf(`\n${heading}\n`)
  assert.notEqual(start, -1, `has a "${heading}" section`)
  const level = heading.split(' ')[0] ?? '##'
  const rest = text.slice(start + heading.length + 2)
  const end = rest.search(new RegExp(`^#{1,${level.length}} `, 'm'))
  return end === -1 ? rest : rest.slice(0, end)
}

function tableRows(text: string): string[][] {
  return text
    .split('\n')
    .filter((line) => line.startsWith('|') && !/^\|\s*-/.test(line))
    .map((line) => line.split('|').slice(1, -1).map((cell) => cell.trim()))
}

function jsonBlocks(text: string): string[] {
  return [...text.matchAll(/```json\n([\s\S]*?)\n```/g)].map((match) => match[1] ?? '')
}

function rendered(value: unknown): string {
  return typeof value === 'string' ? (value === '' ? '`""`' : `\`${value}\``) : `\`${String(value)}\``
}

function loadsCleanly(text: string, layer: 'managed' | 'user'): void {
  const loaded = loadPolicy(
    {
      preset: 'trifecta',
      presetFromManaged: false,
      managed: layer === 'managed' ? { layer, path: '/managed.json', text } : null,
      user: layer === 'user' ? { layer, path: '/user.json', text } : null,
      project: null,
    },
    PRESETS,
  )
  assert.equal(loaded.lockdown, null)
  assert.deepEqual(loaded.warnings, [])
  assert.ok(loaded.layers.some((status) => status.layer === layer && status.status === 'loaded' && status.rules > 0))
}

function subcommands(): string[] {
  const source = read(ROOT, 'hooks', 'register.tsx')
  const start = source.indexOf('async function runCommand(')
  assert.notEqual(start, -1, 'register.tsx has runCommand')
  const body = source.slice(start, source.indexOf('\n}\n', start))
  return [...body.matchAll(/case '([a-z]*)':/g)].map((match) => match[1] ?? '')
}

describe('README options', () => {
  const rows = tableRows(section(readme, '## Options')).slice(1)
  const byKey = new Map(rows.map((cells) => [(cells[0] ?? '').replace(/`/g, ''), cells]))

  it('documents exactly the userConfig keys of plugin.json', () => {
    assert.deepEqual([...byKey.keys()].sort(), Object.keys(manifest.userConfig).sort())
  })

  for (const [key, field] of Object.entries(manifest.userConfig)) {
    it(`documents ${key} with its type and default`, () => {
      const cells = byKey.get(key)
      assert.ok(cells, `README has a row for ${key}`)
      const [, type = '', defaultCell = ''] = cells
      if (field.options !== undefined) {
        for (const option of field.options) assert.match(type, new RegExp(`\`${option}\``), `${key} lists option ${option}`)
      } else {
        assert.equal(type, field.type, `${key} type`)
      }
      assert.equal(defaultCell, rendered(field.default), `${key} default`)
    })
  }
})

describe('README /taintguard', () => {
  const commands = section(readme, '## `/taintguard`')
  const subs = subcommands()

  it('reads the subcommands from the hooks module', () => {
    for (const sub of ['', 'status', 'explain', 'tools', 'clear', 'reload', 'audit']) assert.ok(subs.includes(sub), sub)
  })

  for (const sub of subs) {
    it(`documents /taintguard ${sub === '' ? '(bare)' : sub}`, () => {
      const invocation = sub === '' ? '`/taintguard`' : `\`/taintguard ${sub}`
      assert.ok(commands.includes(invocation), `README documents ${invocation}`)
    })
  }

  it('matches the usage text the command prints', () => {
    const usage = /USAGE =\s*'([^']+)'/.exec(read(ROOT, 'hooks', 'support.ts'))?.[1]
    assert.ok(usage)
    for (const word of ['explain <tool> [json args]', 'clear [label…]']) {
      assert.ok(usage.includes(word))
      assert.ok(commands.includes(`/taintguard ${word}`), word)
    }
  })
})

describe('README example policy', () => {
  const blocks = jsonBlocks(section(readme, '### Example policy'))

  it('is one JSON block that names the published schema', () => {
    assert.equal(blocks.length, 1)
    const policy = JSON.parse(blocks[0] ?? '') as Record<string, unknown>
    assert.equal(policy.$schema, SCHEMA_ID)
  })

  it('validates with validatePolicy', () => {
    const result = validatePolicy(JSON.parse(blocks[0] ?? ''), { layer: 'user' })
    assert.ok(result.ok, result.ok ? '' : result.errors.join('; '))
  })

  it('loads as a user layer without lockdown or warnings', () => {
    loadsCleanly(blocks[0] ?? '', 'user')
  })
})

function apiNamespaces(): string[] {
  const sources = ['register.tsx', 'support.ts'].map((file) => read(ROOT, 'hooks', file))
  const names = sources.flatMap((source) => [...source.matchAll(/\$\.([a-z]+)\./g)].map((match) => match[1] ?? ''))
  return [...new Set(names)].sort()
}

describe('README security model', () => {
  const limitations = section(readme, '### Known limitations and residual risk')
  const rows = tableRows(limitations).slice(1)
  const row = (name: string): string => (rows.find((cells) => cells[0] === name) ?? []).join(' | ')

  it('names the built-in self-protection rule', () => {
    assert.equal(SELF_PROTECT_RULE, 'builtin:self-protect')
    assert.ok(readme.includes(`\`${SELF_PROTECT_RULE}\``))
    assert.ok(section(readme, '### Built-in self-protection').includes(`\`${SELF_PROTECT_RULE}\``))
    assert.ok(deployment.includes(`\`${SELF_PROTECT_RULE}\``))
  })

  it('lists exactly the API namespaces the hooks module calls', () => {
    const used = apiNamespaces()
    assert.deepEqual(used, ['clock', 'command', 'env', 'fs', 'session', 'settings', 'state', 'store', 'ui'])
    const cell = row('Mods are not sandboxed')
    const listed = [...cell.matchAll(/`([a-z]+)` \(/g)].map((match) => match[1] ?? '').sort()
    assert.deepEqual(listed, used)
  })

  it('lists the gaps the evals report', () => {
    for (const name of ['Sources outside the preset families', 'MCP write verbs outside the spec\'s list', 'Self-protection reads Bash text']) {
      assert.notEqual(row(name), '', name)
    }
    assert.match(row('MCP write verbs outside the spec\'s list'), /`push_files`.*`put_object`/)
    assert.ok(limitations.includes('(evals/RESULTS.md#known-gaps-reported-not-gated)'))
    assert.ok(results.includes('\n### Known gaps (reported, not gated)\n'))
  })

  it('documents every preset source and server family', () => {
    for (const source of PRESETS.trifecta?.sources ?? []) assert.ok(readme.includes(`\`preset:${source.id}\``), source.id)
    const families = tableRows(section(readme, '## Presets')).filter((cells) => cells.length === 2)
    for (const [family, tokens] of Object.entries(FAMILY_TOKENS)) {
      const label = family === 'docs' ? 'documents' : family
      const cell = families.find((cells) => cells[0] === label)?.[1] ?? ''
      assert.deepEqual(
        [...cell.matchAll(/`([^`]+)`/g)].map((match) => match[1]),
        [...tokens],
        family,
      )
    }
  })

  it('documents the fail-closed argument cap, the project regex limits and the managed floor', () => {
    const flat = readme.replace(/\s+/g, ' ')
    for (const phrase of ['100,000 characters', 'at most 256 characters', 'at most 50 in the file', 'alternation under an unbounded quantifier', 'The managed floor']) {
      assert.ok(flat.includes(phrase), phrase)
    }
    assert.ok(deployment.includes('The managed floor on the globals'))
  })
})

describe('evaluation results', () => {
  const injection = injectionEval()
  const benign = benignEval()
  const rate = (part: number, whole: number): string => percent(part, whole)

  it('RESULTS.md carries the current injection totals', () => {
    const { strict, trifecta } = injection
    assert.ok(results.includes(`| strict | ${strict.attempts} | 0 | ${strict.denied} | ${strict.askRefused} | 0 executed | met |`))
    assert.ok(results.includes(`| trifecta | ${trifecta.attempts} | 0 | ${trifecta.denied} | ${trifecta.askRefused} | 0 executed without approval | met |`))
    assert.ok(results.includes(`${strict.attempts} exfiltration calls`))
  })

  it('RESULTS.md carries the current gap counts', () => {
    const table = section(results, '### Known gaps (reported, not gated)')
    const counts = tableRows(table)
      .slice(1)
      .map((cells) => cells.slice(-4).join(' | '))
    const expected = [...injection.gaps.values()].map((t) => [t.strict.scenarios, t.none.executed, t.trifecta.executed, t.strict.executed].join(' | '))
    assert.deepEqual(counts, expected)
  })

  it('the README, the release notes and RESULTS.md state the measured benign rates', () => {
    const { trifecta, strict } = benign.byPreset
    const asked = rate(trifecta.hit, trifecta.traces)
    const failed = rate(trifecta.failed, trifecta.traces)
    const strictFailed = rate(strict.failed, strict.traces)
    assert.equal(benign.pass, false)
    const cost = section(readme, '### What the presets cost on ordinary work')
    assert.ok(cost.includes(`| \`trifecta\` | ${asked} | ${failed} |`), cost)
    assert.ok(cost.includes(`| \`strict\` | ${rate(strict.hit, strict.traces)} | ${strictFailed} |`), cost)
    const notes = releaseNotes.replace(/\s+/g, ' ')
    assert.ok(notes.includes(`${asked} of tasks hit an ask`))
    assert.ok(notes.includes(`${failed} could not finish`))
    assert.ok(notes.includes(`${strictFailed} could not finish`))
    assert.ok(results.includes(`| hit an ask or refusal < 5% | ${asked} | **missed** |`))
    assert.ok(results.includes(`| could not finish < 1% | ${failed} | **missed** |`))
  })
})

describe('deployment guide', () => {
  it('lists TaintGuard in prependPlugins ahead of the built-in guard', () => {
    assert.match(deployment, /prependPlugins/)
    assert.ok(deployment.includes('"prependPlugins": ["taint-guard@acme-security", "sec-default@builtin"]'))
    assert.ok(deployment.includes('["taint-guard@<marketplace>", "sec-default@builtin"]'))
  })

  it('pins the managed options under pluginConfigs', () => {
    for (const word of ['managedPolicyPath', 'pluginConfigs', '"enabled": true', '"preset"', 'tier prepend']) {
      assert.ok(deployment.includes(word), word)
    }
  })

  it('has a managed settings example and a managed policy that loads cleanly', () => {
    const blocks = jsonBlocks(deployment).map((text) => JSON.parse(text) as Record<string, unknown>)
    const settings = blocks.find((block) => 'prependPlugins' in block)
    assert.ok(settings)
    const options = (settings.pluginConfigs as Record<string, { options: Record<string, unknown> }>)['taint-guard@acme-security']?.options
    assert.ok(options)
    for (const key of Object.keys(options)) assert.ok(key in manifest.userConfig, key)
    const policy = blocks.find((block) => block.version === 1)
    assert.ok(policy)
    assert.equal(policy.$schema, SCHEMA_ID)
    assert.ok(validatePolicy(policy, { layer: 'managed' }).ok)
    loadsCleanly(JSON.stringify(policy), 'managed')
  })

  it('is linked from the README', () => {
    assert.ok(readme.includes('(docs/deployment.md)'))
  })
})

describe('release metadata', () => {
  it('plugin.json, package.json and package-lock.json agree on the version', () => {
    assert.equal(manifest.name, 'taint-guard')
    assert.match(manifest.version, /^\d+\.\d+\.\d+$/)
    for (const version of [pkg.version, lock.version, lock.packages['']?.version]) assert.equal(version, manifest.version)
  })

  it('has release notes for the version', () => {
    const notes = join(ROOT, 'releases', `${manifest.version}.md`)
    assert.ok(existsSync(notes), `releases/${manifest.version}.md exists`)
    assert.match(read(notes), new RegExp(`^# TaintGuard ${manifest.version.replace(/\./g, '\\.')}\\n`))
  })

  it('the release workflow can release taint-guard, gated on its own CI', () => {
    const release = read(REPO, '.github', 'workflows', 'artifact-release.yml')
    assert.match(release, /^ {10}- taint-guard$/m)
    assert.match(release, /'taint-guard'\]\.includes\(plugin\)/)
    assert.match(release, /taint-guard\) workflow=taint-guard\.yml ;;/)
  })

  it('the root README lists the plugin', () => {
    assert.match(read(REPO, 'README.md'), /^\| `taint-guard` \|.*\| \[`plugins\/taint-guard`\]\(plugins\/taint-guard\) \| `\/taintguard` \|$/m)
  })
})

describe('CI workflow', () => {
  it('exists', () => {
    assert.ok(existsSync(workflowPath), '.github/workflows/taint-guard.yml exists')
  })

  const workflow = existsSync(workflowPath) ? read(workflowPath) : ''

  it('triggers on the plugin folder and itself, and by hand', () => {
    for (const event of ['push', 'pull_request']) {
      const block = new RegExp(`^ {2}${event}:\\n([\\s\\S]*?)(?=^ {2}\\w)`, 'm').exec(workflow)?.[1] ?? ''
      assert.match(block, /- 'plugins\/taint-guard\/\*\*'/, event)
      assert.match(block, /- '\.github\/workflows\/taint-guard\.yml'/, event)
    }
    assert.match(workflow, /^ {2}workflow_dispatch:/m)
    assert.match(workflow, /working-directory: plugins\/taint-guard\n/)
  })

  it('validates strictly and runs the hooks suites with Claude Code', () => {
    assert.match(workflow, /npm install -g @anthropic-ai\/claude-code/)
    assert.match(workflow, /claude plugin validate --strict plugins\/taint-guard\n/)
    assert.match(workflow, /claude plugin test plugins\/taint-guard\n/)
  })

  it('typechecks, runs the unit tests on every OS and checks the generated presets', () => {
    assert.match(workflow, /run: npm run typecheck\n/)
    assert.match(workflow, /run: npm run test:unit\n/)
    assert.match(workflow, /run: node scripts\/presets\.ts --check\n/)
    assert.match(workflow, /os: \[ubuntu-latest, macos-latest, windows-latest\]/)
    assert.match(workflow, /node-version: \['22\.18\.0', '24'\]/)
  })

  it('runs the real-session end-to-end test', () => {
    assert.match(workflow, /run: npm run test:e2e\n/)
  })

  it('every npm run in the workflow names a package script', () => {
    const used = [...workflow.matchAll(/npm run ([\w:-]+)/g)].map((match) => match[1] ?? '')
    for (const name of used) assert.ok(name in pkg.scripts, `package.json has script ${name}`)
  })

  it('every npm run the README lists names a package script', () => {
    const used = [...section(readme, '## Development').matchAll(/npm run ([\w:-]+)/g)].map((match) => match[1] ?? '')
    assert.ok(used.length >= 8)
    for (const name of used) assert.ok(name in pkg.scripts, `package.json has script ${name}`)
  })
})
