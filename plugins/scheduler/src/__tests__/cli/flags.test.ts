import { describe, it, expect } from 'vitest';
import { parseArgs } from 'node:util';
import { isFlagSet, parseAddArgs } from '../../cli/flags.js';

function parseClearModel(args: string[]): boolean {
  const { values } = parseArgs({
    args,
    options: { 'clear-model': { type: 'boolean', default: false } },
    strict: false,
  });
  return isFlagSet(values['clear-model']);
}

describe('isFlagSet', () => {
  it('is set by a bare flag', () => {
    expect(parseClearModel(['--clear-model'])).toBe(true);
  });

  it('is set by an explicit true', () => {
    expect(parseClearModel(['--clear-model=true'])).toBe(true);
  });

  it('is not set by an explicit false', () => {
    expect(parseClearModel(['--clear-model=false'])).toBe(false);
  });

  it('is not set when the flag is absent', () => {
    expect(parseClearModel([])).toBe(false);
  });
});

describe('parseAddArgs', () => {
  it('maps every option onto the add arguments', () => {
    expect(
      parseAddArgs([
        '--name', 'nightly',
        '--cron', '0 2 * * *',
        '--command', 'review',
        '--working-directory', '/repo',
        '--timeout', '600',
        '--description', 'Nightly review',
        '--model', 'haiku',
        '--effort', 'low',
        '--skip-permissions',
        '--memory',
      ]),
    ).toEqual({
      name: 'nightly',
      cron: '0 2 * * *',
      command: 'review',
      workingDirectory: '/repo',
      timeout: 600,
      skipPermissions: true,
      description: 'Nightly review',
      memory: true,
      model: 'haiku',
      effort: 'low',
    });
  });

  it.each([
    [[], false],
    [['--skip-permissions'], true],
    [['--skip-permissions=true'], true],
    [['--skip-permissions=false'], false],
  ])('reads skip-permissions from %j as %s', (args, expected) => {
    expect(parseAddArgs(args).skipPermissions).toBe(expected);
  });

  it.each([
    [[], false],
    [['--memory'], true],
    [['--memory=true'], true],
    [['--memory=false'], false],
  ])('reads memory from %j as %s', (args, expected) => {
    expect(parseAddArgs(args).memory).toBe(expected);
  });
});
