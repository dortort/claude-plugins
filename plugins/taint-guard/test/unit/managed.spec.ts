import { describe, it } from 'node:test'
import assert from 'node:assert/strict'
import { effectivePreset, expandHome, ignoredManagedPathWarning, managedOptionsFrom } from '../../src/managed.ts'
import type { ManagedOptions } from '../../src/managed.ts'

describe('managedOptionsFrom', () => {
  const cases: Array<[string, unknown, ManagedOptions]> = [
    ['undefined settings', undefined, {}],
    ['null settings', null, {}],
    ['a string', 'policy', {}],
    ['an array', [], {}],
    ['no pluginConfigs', { other: 1 }, {}],
    ['pluginConfigs not an object', { pluginConfigs: [1, 2] }, {}],
    ['entry not an object', { pluginConfigs: { 'taint-guard@m': 'x' } }, {}],
    ['options missing', { pluginConfigs: { 'taint-guard@m': {} } }, {}],
    ['options an array', { pluginConfigs: { 'taint-guard@m': { options: [] } } }, {}],
    [
      'every option set',
      { pluginConfigs: { 'taint-guard@corp': { options: { enabled: true, preset: 'strict', managedPolicyPath: '/etc/tg.json' } } } },
      { enabled: true, preset: 'strict', managedPolicyPath: '/etc/tg.json' },
    ],
    ['bare plugin name', { pluginConfigs: { 'taint-guard': { options: { preset: 'none' } } } }, { preset: 'none' }],
    [
      'other plugins ignored',
      {
        pluginConfigs: {
          'taint-guard-extra@m': { options: { enabled: true } },
          'other@m': { options: { preset: 'strict' } },
          'xtaint-guard@m': { options: { managedPolicyPath: '/x' } },
        },
      },
      {},
    ],
    [
      'wrong types ignored',
      { pluginConfigs: { 'taint-guard@m': { options: { enabled: 'true', preset: 'paranoid', managedPolicyPath: 42 } } } },
      {},
    ],
    ['enabled false is not a lock', { pluginConfigs: { 'taint-guard@m': { options: { enabled: false } } } }, {}],
    ['empty path ignored', { pluginConfigs: { 'taint-guard@m': { options: { managedPolicyPath: '' } } } }, {}],
    [
      'strictest preset and any enabled across entries',
      {
        pluginConfigs: {
          'taint-guard@b': { options: { preset: 'strict', enabled: false } },
          'taint-guard@a': { options: { preset: 'trifecta', enabled: true } },
          'taint-guard@c': { options: { preset: 'none' } },
        },
      },
      { enabled: true, preset: 'strict' },
    ],
    [
      'first non-empty path in sorted key order',
      {
        pluginConfigs: {
          'taint-guard@z': { options: { managedPolicyPath: '/z.json' } },
          'taint-guard@b': { options: { managedPolicyPath: '/b.json' } },
          'taint-guard@a': { options: { managedPolicyPath: '' } },
        },
      },
      { managedPolicyPath: '/b.json' },
    ],
  ]
  for (const [name, settings, expected] of cases) {
    it(name, () => {
      assert.deepEqual(managedOptionsFrom(settings, 'taint-guard'), expected)
    })
  }

  it('handles a null-prototype pluginConfigs with null options', () => {
    const configs = Object.create(null) as Record<string, unknown>
    configs['taint-guard@m'] = { options: null }
    assert.deepEqual(managedOptionsFrom({ pluginConfigs: configs }, 'taint-guard'), {})
  })
})

describe('effectivePreset', () => {
  const cases: Array<[unknown, ManagedOptions, { preset: string; fromManaged: boolean }]> = [
    [undefined, {}, { preset: 'trifecta', fromManaged: false }],
    ['bogus', {}, { preset: 'trifecta', fromManaged: false }],
    [42, {}, { preset: 'trifecta', fromManaged: false }],
    ['none', {}, { preset: 'none', fromManaged: false }],
    ['strict', {}, { preset: 'strict', fromManaged: false }],
    ['none', { preset: 'trifecta' }, { preset: 'trifecta', fromManaged: true }],
    ['strict', { preset: 'trifecta' }, { preset: 'strict', fromManaged: true }],
    ['trifecta', { preset: 'none' }, { preset: 'trifecta', fromManaged: true }],
    ['none', { preset: 'none' }, { preset: 'none', fromManaged: true }],
    [undefined, { preset: 'strict' }, { preset: 'strict', fromManaged: true }],
  ]
  for (const [user, managed, expected] of cases) {
    it(`user ${String(user)}, managed ${managed.preset ?? 'unset'}`, () => {
      assert.deepEqual(effectivePreset(user, managed), expected)
    })
  }
})

describe('expandHome', () => {
  const cases: Array<[string, string | undefined, string]> = [
    ['~', '/home/u', '/home/u'],
    ['~/.claude/taint-guard.json', '/home/u', '/home/u/.claude/taint-guard.json'],
    ['~/x', '/home/u/', '/home/u/x'],
    ['~\\x', 'C:\\Users\\u', 'C:\\Users\\u\\x'],
    ['~/x', undefined, '~/x'],
    ['~/x', '', '~/x'],
    ['~user/x', '/home/u', '~user/x'],
    ['/abs/~/x', '/home/u', '/abs/~/x'],
    ['rel/x', '/home/u', 'rel/x'],
    ['', '/home/u', ''],
  ]
  for (const [path, home, expected] of cases) {
    it(`${path} with home ${String(home)}`, () => {
      assert.equal(expandHome(path, home), expected)
    })
  }
})

describe('ignoredManagedPathWarning', () => {
  const warning = 'managedPolicyPath in user settings is ignored; only managed settings can set it'
  const cases: Array<[unknown, ManagedOptions, string | null]> = [
    [undefined, {}, null],
    ['', {}, null],
    [42, {}, null],
    ['/u/x.json', {}, warning],
    ['/u/x.json', { managedPolicyPath: '/etc/tg.json' }, warning],
    ['/etc/tg.json', { managedPolicyPath: '/etc/tg.json' }, null],
  ]
  for (const [value, managed, expected] of cases) {
    it(`${String(value)} against ${managed.managedPolicyPath ?? 'none'}`, () => {
      assert.equal(ignoredManagedPathWarning(value, managed), expected)
    })
  }
})
