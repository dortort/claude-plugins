import { describe, it, expect } from 'vitest';
import { parseArgs } from 'node:util';
import { isFlagSet } from '../../cli/flags.js';

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
