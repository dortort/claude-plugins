import { describe, it, expect } from 'vitest';
import { parseArgs } from 'node:util';
import { isFlagSet, parseAddArgs, parseUpdateArgs } from '../../cli/flags.js';

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

  it.each([
    [['--skip-permissions', 'false']],
    [['--memory', 'false']],
    [['--name', 'nightly', 'extra']],
  ])('rejects the stray value in %j', (args) => {
    expect(() => parseAddArgs(args)).toThrow(/Unexpected argument/);
  });
});

describe('parseUpdateArgs', () => {
  it('maps every option onto the update arguments', () => {
    expect(
      parseUpdateArgs([
        '--id', 'task-1',
        '--cron', '0 2 * * *',
        '--command', 'review',
        '--timeout', '600',
        '--enabled', 'false',
        '--name', 'nightly',
        '--description', 'Nightly review',
        '--memory', 'true',
        '--model', 'haiku',
        '--effort', 'low',
      ]),
    ).toEqual({
      id: 'task-1',
      cron: '0 2 * * *',
      command: 'review',
      timeout: 600,
      enabled: false,
      name: 'nightly',
      description: 'Nightly review',
      memory: true,
      model: 'haiku',
      effort: 'low',
      clearModel: false,
      clearEffort: false,
    });
  });

  it('leaves enabled and memory unset when they are not given', () => {
    const parsed = parseUpdateArgs(['--id', 'task-1']);
    expect(parsed.enabled).toBeUndefined();
    expect(parsed.memory).toBeUndefined();
  });

  it.each([
    [['--clear-model'], true],
    [['--clear-model=true'], true],
    [['--clear-model=false'], false],
  ])('reads clear-model from %j as %s', (args, expected) => {
    expect(parseUpdateArgs(['--id', 'task-1', ...args]).clearModel).toBe(expected);
  });

  it.each([
    [['--clear-model', 'false']],
    [['--clear-effort', 'false']],
  ])('rejects the stray value in %j', (args) => {
    expect(() => parseUpdateArgs(['--id', 'task-1', ...args])).toThrow(/Unexpected argument/);
  });
});
