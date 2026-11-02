import { readdirSync, readFileSync } from 'node:fs'
import { join } from 'node:path'
import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { Ajv2020, type ErrorObject } from 'ajv/dist/2020.js'
import { SCHEMA_ID } from '../../src/presets.ts'

const ROOT = join(import.meta.dirname, '..', '..')
const FIXTURES = join(ROOT, 'tests', 'fixtures', 'policies')

const readJson = (path: string): unknown => JSON.parse(readFileSync(path, 'utf8'))
const jsonFiles = (dir: string): string[] =>
  readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .sort()

const schema = readJson(join(ROOT, 'schema', 'taint-guard.schema.json')) as Record<string, unknown>

function compile() {
  const ajv = new Ajv2020({ allErrors: true, strict: true })
  ajv.addFormat('regex', {
    type: 'string',
    validate: (text: string) => {
      try {
        new RegExp(text)
        return true
      } catch {
        return false
      }
    },
  })
  return ajv.compile(schema)
}

const validate = compile()
const errorsOf = (): string => JSON.stringify(validate.errors, null, 2)

describe('policy schema', () => {
  it('declares draft 2020-12 and the published $id', () => {
    assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema')
    assert.equal(schema.$id, SCHEMA_ID)
    assert.equal(typeof schema.title, 'string')
  })

  it('compiles under Ajv strict mode', () => {
    assert.equal(typeof validate, 'function')
  })

  for (const file of jsonFiles(join(ROOT, 'presets'))) {
    it(`accepts presets/${file}`, () => {
      const preset = readJson(join(ROOT, 'presets', file)) as Record<string, unknown>
      assert.equal(validate(preset), true, errorsOf())
      assert.equal(preset.$schema, SCHEMA_ID)
    })
  }

  const valid = jsonFiles(join(FIXTURES, 'valid'))
  it('has valid fixtures', () => {
    for (const name of ['example.json', 'minimal.json', 'references.json']) assert.ok(valid.includes(name), name)
  })
  for (const file of valid) {
    it(`accepts valid/${file}`, () => {
      assert.equal(validate(readJson(join(FIXTURES, 'valid', file))), true, errorsOf())
    })
  }

  const invalid = jsonFiles(join(FIXTURES, 'invalid'))
  it('has at least 15 invalid fixtures', () => {
    assert.ok(invalid.length >= 15, `${invalid.length} invalid fixtures`)
  })
  for (const file of invalid) {
    it(`rejects invalid/${file}`, () => {
      assert.equal(validate(readJson(join(FIXTURES, 'invalid', file))), false)
    })
  }

  it('rejects a selector regex that does not compile', () => {
    const policy = {
      version: 1,
      labels: { a: {} },
      sources: [{ id: 's', match: { tool: { regex: '(' } }, taints: ['a'] }],
    }
    assert.equal(validate(policy), false)
    assert.ok(validate.errors?.some((error: ErrorObject) => error.keyword === 'format'))
  })

  it('accepts the example policy only with version 1', () => {
    const example = readJson(join(FIXTURES, 'valid', 'example.json')) as Record<string, unknown>
    assert.equal(validate({ ...example, version: 1 }), true)
    assert.equal(validate({ ...example, version: 1.5 }), false)
  })
})
