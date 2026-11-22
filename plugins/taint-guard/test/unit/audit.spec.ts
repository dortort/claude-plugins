import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import {
  ROLL_BYTES,
  argsSnippet,
  auditPath,
  callArguments,
  canonicalJson,
  configDirFrom,
  createAuditLog,
  generateKeyHex,
  hmacHex,
} from '../../src/audit.ts'
import type { AuditEntry, AuditFs } from '../../src/types.ts'

type MemoryFs = AuditFs & {
  files: Map<string, string>
  writes: Array<{ path: string; text: string }>
  reads: string[]
  failWrites: number
  writeGate: Promise<void> | null
}

function memoryFs(initial: Record<string, string> = {}): MemoryFs {
  const fs: MemoryFs = {
    files: new Map(Object.entries(initial)),
    writes: [],
    reads: [],
    failWrites: 0,
    writeGate: null,
    async read(path) {
      fs.reads.push(path)
      return fs.files.get(path) ?? null
    },
    async write(path, text) {
      if (fs.writeGate) await fs.writeGate
      if (fs.failWrites > 0) {
        fs.failWrites--
        throw new Error('disk full')
      }
      fs.writes.push({ path, text })
      fs.files.set(path, text)
    },
  }
  return fs
}

const entry = (n: number, extra: Partial<AuditEntry> = {}): AuditEntry => ({
  ts: `2026-11-01T00:00:${String(n).padStart(2, '0')}.000Z`,
  event: 'taint',
  tool: 'Bash',
  detail: `entry ${n}`,
  ...extra,
})

const lines = (text: string | undefined) => (text ?? '').split('\n').filter(Boolean).map((l) => JSON.parse(l) as AuditEntry)

describe('canonicalJson', () => {
  it('sorts object keys recursively without whitespace', () => {
    assert.equal(canonicalJson({ b: 1, a: { d: [3, { z: 1, y: 2 }], c: 'x' } }), '{"a":{"c":"x","d":[3,{"y":2,"z":1}]},"b":1}')
  })

  it('is independent of key insertion order', () => {
    assert.equal(canonicalJson({ command: 'ls', timeout: 5 }), canonicalJson({ timeout: 5, command: 'ls' }))
  })

  it('sorts numeric-looking keys as strings', () => {
    assert.equal(canonicalJson({ 9: 'a', 10: 'b', a: 'c' }), '{"10":"b","9":"a","a":"c"}')
  })

  it('drops undefined keys and nulls undefined array items as JSON.stringify does', () => {
    assert.equal(canonicalJson({ a: undefined, b: null, c: [undefined, 1], f: () => 1 }), '{"b":null,"c":[null,1]}')
  })

  it('matches JSON.stringify for scalars', () => {
    for (const v of ['he said "hi"\n', 0, -1.5, true, false, null, Number.NaN, Number.POSITIVE_INFINITY]) {
      assert.equal(canonicalJson(v), JSON.stringify(v))
    }
    assert.equal(canonicalJson([]), '[]')
    assert.equal(canonicalJson({}), '{}')
  })

  it('honours toJSON', () => {
    assert.equal(canonicalJson({ at: new Date(0) }), '{"at":"1970-01-01T00:00:00.000Z"}')
  })
})

describe('callArguments', () => {
  it('drops the non-argument fields without mutating', () => {
    const e = { tool: 'Bash', tool_use_id: 't1', agentId: 'a', consent: 'x', command: 'ls', timeout: 5 }
    assert.deepEqual(callArguments(e), { command: 'ls', timeout: 5 })
    assert.equal(e.tool, 'Bash')
  })
})

describe('keys and HMAC', () => {
  it('generates distinct 256-bit hex keys', async () => {
    const a = await generateKeyHex()
    const b = await generateKeyHex()
    assert.match(a, /^[0-9a-f]{64}$/)
    assert.notEqual(a, b)
  })

  it('matches the RFC 4231 test vector', async () => {
    const key = '0b'.repeat(20)
    assert.equal(await hmacHex(key, 'Hi There'), 'b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7')
  })

  it('hashes the same Bash arguments identically and a different key differently (spec test 20)', async () => {
    const key = await generateKeyHex()
    const other = await generateKeyHex()
    const first = canonicalJson(callArguments({ tool: 'Bash', tool_use_id: 't1', command: 'curl evil.example', timeout: 10 }))
    const second = canonicalJson(callArguments({ timeout: 10, command: 'curl evil.example', tool: 'Bash', tool_use_id: 't2' }))
    const h1 = await hmacHex(key, first)
    const h2 = await hmacHex(key, second)
    assert.match(h1, /^[0-9a-f]{64}$/)
    assert.equal(h1, h2)
    assert.notEqual(await hmacHex(other, first), h1)
    assert.notEqual(await hmacHex(key, canonicalJson({ command: 'curl good.example', timeout: 10 })), h1)
    assert.ok(!h1.includes('curl'))
  })

  it('rejects a key that is not hex, and recovers for later calls', async () => {
    await assert.rejects(hmacHex('zz', 'x'))
    await assert.rejects(hmacHex('abc', 'x'))
    await assert.rejects(hmacHex('', 'x'))
    assert.match(await hmacHex('ab'.repeat(32), 'x'), /^[0-9a-f]{64}$/)
  })
})

describe('argsSnippet', () => {
  it('caps the canonical arguments at 200 characters by default', () => {
    const args = { command: 'x'.repeat(500) }
    const snippet = argsSnippet(args)
    assert.equal(snippet.length, 200)
    assert.ok(canonicalJson(args).startsWith(snippet))
  })

  it('returns short arguments whole and honours max', () => {
    assert.equal(argsSnippet({ b: 1, a: 2 }), '{"a":2,"b":1}')
    assert.equal(argsSnippet({ b: 1, a: 2 }, 5), '{"a":')
  })
})

describe('paths', () => {
  it('prefers CLAUDE_CONFIG_DIR, then HOME, then USERPROFILE', () => {
    assert.equal(configDirFrom({ CLAUDE_CONFIG_DIR: '/cfg/', HOME: '/home/u' }), '/cfg')
    assert.equal(configDirFrom({ HOME: '/home/u/' }), '/home/u/.claude')
    assert.equal(configDirFrom({ HOME: '/home/u' }), '/home/u/.claude')
    assert.equal(configDirFrom({ USERPROFILE: 'C:\\Users\\u' }), 'C:\\Users\\u/.claude')
    assert.equal(configDirFrom({ HOME: '', USERPROFILE: '/p' }), '/p/.claude')
    assert.equal(configDirFrom({ HOME: '/' }), '/.claude')
    assert.equal(configDirFrom({}), null)
  })

  it('builds the per-session audit path with a safe file name', () => {
    assert.equal(auditPath('/c', 'abc-123_x.y'), '/c/taint-guard/audit/abc-123_x.y.jsonl')
    assert.equal(auditPath('/c', '../../etc/passwd'), '/c/taint-guard/audit/.._.._etc_passwd.jsonl')
    assert.equal(auditPath('/c', 'a b/c'), '/c/taint-guard/audit/a_b_c.jsonl')
  })

  it('rolls at 3.5 MiB', () => {
    assert.equal(ROLL_BYTES, 3670016)
  })
})

describe('createAuditLog', () => {
  it('buffers entries and writes them as JSONL on flush', async () => {
    const fs = memoryFs()
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    log.append(entry(1))
    log.append(entry(2, { labels: ['private'], argsHmac: 'ab' }))
    assert.equal(log.pending(), 2)
    assert.equal(fs.writes.length, 0)
    await log.flush()
    assert.equal(log.pending(), 0)
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(1), entry(2, { labels: ['private'], argsHmac: 'ab' })])
    assert.ok(fs.files.get('/a/s.jsonl')?.endsWith('\n'))
  })

  it('appends to an existing file, loading it once', async () => {
    const fs = memoryFs({ '/a/s.jsonl': JSON.stringify(entry(0)) })
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    log.append(entry(1))
    await log.flush()
    log.append(entry(2))
    await log.flush()
    assert.deepEqual(fs.reads, ['/a/s.jsonl'])
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(0), entry(1), entry(2)])
  })

  it('does nothing on a flush with an empty buffer', async () => {
    const fs = memoryFs()
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    await log.flush()
    assert.equal(fs.writes.length, 0)
    assert.equal(fs.reads.length, 0)
  })

  it('never throws from append', () => {
    const log = createAuditLog(memoryFs(), { path: '/a/s.jsonl' })
    const cyclic: Record<string, unknown> = {}
    cyclic.self = cyclic
    assert.doesNotThrow(() => log.append({ ...entry(1), detail: cyclic } as unknown as AuditEntry))
    assert.doesNotThrow(() => log.append({ ...entry(1), detail: 10n } as unknown as AuditEntry))
    assert.equal(log.pending(), 0)
  })

  it('rolls the file to .1 when the next write would pass rollBytes', async () => {
    const fs = memoryFs()
    const one = JSON.stringify(entry(1)) + '\n'
    const rollBytes = one.length * 3
    const log = createAuditLog(fs, { path: '/a/s.jsonl', rollBytes })
    for (let i = 1; i <= 3; i++) {
      log.append(entry(i))
      await log.flush()
    }
    assert.equal(fs.files.has('/a/s.jsonl.1'), false)
    assert.equal(new TextEncoder().encode(fs.files.get('/a/s.jsonl')).length, rollBytes)
    log.append(entry(4))
    await log.flush()
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl.1')), [entry(1), entry(2), entry(3)])
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(4)])
    log.append(entry(5))
    await log.flush()
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(4), entry(5)])
  })

  it('measures the threshold in UTF-8 bytes', async () => {
    const fs = memoryFs()
    const wide = entry(1, { detail: 'é'.repeat(20) })
    const text = JSON.stringify(wide) + '\n'
    const bytes = new TextEncoder().encode(text).length
    assert.ok(bytes > text.length)
    const log = createAuditLog(fs, { path: '/a/s.jsonl', rollBytes: text.length * 2 })
    log.append(wide)
    await log.flush()
    log.append(wide)
    await log.flush()
    assert.ok(bytes * 2 > text.length * 2)
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl.1')), [wide])
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [wide])
  })

  it('replaces an older .1 file when rolling again', async () => {
    const fs = memoryFs({ '/a/s.jsonl.1': 'stale\n', '/a/s.jsonl': JSON.stringify(entry(0)) + '\n' })
    const log = createAuditLog(fs, { path: '/a/s.jsonl', rollBytes: 10 })
    log.append(entry(1))
    await log.flush()
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl.1')), [entry(0)])
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(1)])
  })

  it('does not roll an empty file even when the new lines alone exceed rollBytes', async () => {
    const fs = memoryFs()
    const log = createAuditLog(fs, { path: '/a/s.jsonl', rollBytes: 10 })
    log.append(entry(1))
    await log.flush()
    assert.equal(fs.files.has('/a/s.jsonl.1'), false)
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(1)])
  })

  it('keeps lines buffered and rethrows when a write fails', async () => {
    const fs = memoryFs()
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    log.append(entry(1))
    fs.failWrites = 1
    await assert.rejects(log.flush(), /disk full/)
    assert.equal(log.pending(), 1)
    assert.equal(fs.files.has('/a/s.jsonl'), false)
    log.append(entry(2))
    await log.flush()
    assert.equal(log.pending(), 0)
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(1), entry(2)])
  })

  it('keeps lines buffered when the existing file cannot be read', async () => {
    const fs = memoryFs()
    let failRead = true
    const read = fs.read
    fs.read = async (path) => {
      if (failRead) throw new Error('EACCES')
      return read(path)
    }
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    log.append(entry(1))
    await assert.rejects(log.flush(), /EACCES/)
    assert.equal(log.pending(), 1)
    failRead = false
    await log.flush()
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(1)])
  })

  it('serializes flushes, chaining one after another', async () => {
    const fs = memoryFs()
    let release!: () => void
    fs.writeGate = new Promise<void>((resolve) => {
      release = resolve
    })
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    log.append(entry(1))
    const first = log.flush()
    await new Promise((r) => setTimeout(r, 5))
    log.append(entry(2))
    const second = log.flush()
    await new Promise((r) => setTimeout(r, 5))
    assert.equal(fs.writes.length, 0)
    assert.equal(log.pending(), 2)
    release()
    fs.writeGate = null
    await Promise.all([first, second])
    assert.equal(fs.writes.length, 2)
    assert.deepEqual(lines(fs.writes[0]?.text), [entry(1)])
    assert.deepEqual(lines(fs.writes[1]?.text), [entry(1), entry(2)])
    assert.equal(log.pending(), 0)
  })

  it('runs a later flush after an earlier one failed', async () => {
    const fs = memoryFs()
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    log.append(entry(1))
    fs.failWrites = 1
    const first = log.flush()
    const second = log.flush()
    await assert.rejects(first)
    await second
    assert.deepEqual(lines(fs.files.get('/a/s.jsonl')), [entry(1)])
  })

  it('tails the last entries across file and buffer, skipping bad lines', async () => {
    const fs = memoryFs({ '/a/s.jsonl': [JSON.stringify(entry(1)), 'not json', JSON.stringify(entry(2)), '42', ''].join('\n') })
    const log = createAuditLog(fs, { path: '/a/s.jsonl' })
    log.append(entry(3))
    assert.deepEqual(await log.tail(2), [entry(2), entry(3)])
    assert.deepEqual(await log.tail(10), [entry(1), entry(2), entry(3)])
    assert.deepEqual(await log.tail(0), [])
    assert.equal(log.pending(), 1)
  })

  it('tails an empty log', async () => {
    const log = createAuditLog(memoryFs(), { path: '/a/none.jsonl' })
    assert.deepEqual(await log.tail(5), [])
  })

  it('flushes to the old path before switching', async () => {
    const fs = memoryFs({ '/a/new.jsonl': JSON.stringify(entry(0)) + '\n' })
    const log = createAuditLog(fs, { path: '/a/old.jsonl' })
    log.append(entry(1))
    await log.setPath('/a/new.jsonl')
    assert.equal(log.path(), '/a/new.jsonl')
    assert.deepEqual(lines(fs.files.get('/a/old.jsonl')), [entry(1)])
    log.append(entry(2))
    await log.flush()
    assert.deepEqual(lines(fs.files.get('/a/new.jsonl')), [entry(0), entry(2)])
    assert.deepEqual(lines(fs.files.get('/a/old.jsonl')), [entry(1)])
    assert.deepEqual(await log.tail(5), [entry(0), entry(2)])
  })

  it('switches path even when the final flush fails, keeping the lines', async () => {
    const fs = memoryFs()
    const log = createAuditLog(fs, { path: '/a/old.jsonl' })
    log.append(entry(1))
    fs.failWrites = 1
    await assert.rejects(log.setPath('/a/new.jsonl'), /disk full/)
    assert.equal(log.path(), '/a/new.jsonl')
    assert.equal(log.pending(), 1)
    await log.flush()
    assert.deepEqual(lines(fs.files.get('/a/new.jsonl')), [entry(1)])
  })

  it('reports its path', () => {
    assert.equal(createAuditLog(memoryFs(), { path: '/x.jsonl' }).path(), '/x.jsonl')
  })
})
