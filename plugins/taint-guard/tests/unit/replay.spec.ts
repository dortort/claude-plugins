import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { presetPolicy, replay, untold, type Step, type Truth } from '../../evals/lib/replay.ts'

const trifecta = presetPolicy('trifecta')
const strict = presetPolicy('strict')
const readFile = (file_path: string, truth?: Truth): Step => ({ tool: 'Read', args: { file_path }, ...(truth === undefined ? {} : { truth }) })
const readMail = (truth?: Truth): Step => ({ tool: 'mcp__gmail__read_email', args: { messageId: 'a' }, ...(truth === undefined ? {} : { truth }) })
const shell: Step = { tool: 'Bash', args: { command: 'npm test' } }

describe('benign replay gate classification', () => {
  it('a refusal after a real secret is a designed gate', () => {
    const [, result] = replay(trifecta, [readFile('.env', { secret: true }), shell], 'allow')
    assert.equal(result?.decision, 'deny')
    assert.equal(result?.gate, 'designed')
    assert.deepEqual(result?.genuineBefore, ['secret'])
  })

  it('a refusal after a public certificate labelled secret is a misfire', () => {
    const [, result] = replay(trifecta, [readFile('test/fixtures/localhost.pem', { secret: false }), shell], 'allow')
    assert.equal(result?.decision, 'deny')
    assert.equal(result?.gate, 'misfire')
    assert.deepEqual(result?.labelsBefore, ['secret'])
    assert.deepEqual(result?.genuineBefore, [])
  })

  it('an allOf ask needs every listed label genuine', () => {
    const [, designed] = replay(trifecta, [readMail({ private: true, untrusted: true }), shell], 'allow')
    assert.equal(designed?.decision, 'ask')
    assert.equal(designed?.gate, 'designed')
    const [, misfire] = replay(trifecta, [readMail({ private: true, untrusted: false }), shell], 'allow')
    assert.equal(misfire?.decision, 'ask')
    assert.equal(misfire?.gate, 'misfire')
  })

  it('an anyOf refusal needs one listed label genuine', () => {
    const [, result] = replay(strict, [readMail({ private: false, untrusted: true }), shell], 'allow')
    assert.equal(result?.decision, 'deny')
    assert.equal(result?.gate, 'designed')
  })

  it('a later genuine firing of a held label makes it genuine', () => {
    const results = replay(trifecta, [readFile('test/fixtures/localhost.pem', { secret: false }), readFile('.env', { secret: true }), shell], 'allow')
    assert.equal(results[2]?.gate, 'designed')
  })

  it('allowed calls carry no gate', () => {
    const [result] = replay(trifecta, [shell], 'allow')
    assert.equal(result?.decision, 'allow')
    assert.equal(result?.gate, undefined)
  })

  it('untold names the labels a step can add without ground truth', () => {
    assert.deepEqual(untold(trifecta, readFile('.env')), ['secret'])
    assert.deepEqual(untold(trifecta, readFile('.env', { secret: true })), [])
    assert.deepEqual(untold(trifecta, readMail({ private: true })), ['untrusted'])
    assert.deepEqual(untold(trifecta, shell), [])
  })
})
