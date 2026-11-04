import { parseArgs } from 'node:util';
import type { AddArgs } from './commands/add.js';
import type { UpdateArgs } from './commands/update.js';

export function isFlagSet(value: string | boolean | undefined): boolean {
  return value === true || value === 'true';
}

function rejectPositionals(positionals: string[]): void {
  if (positionals.length > 0) {
    throw new Error(
      `Unexpected argument "${positionals[0]}". Boolean flags take no separate value; use --flag or --flag=false.`,
    );
  }
}

export function parseAddArgs(args: string[]): AddArgs {
  const { values, positionals } = parseArgs({
    args,
    options: {
      name: { type: 'string' },
      cron: { type: 'string' },
      command: { type: 'string' },
      'working-directory': { type: 'string' },
      timeout: { type: 'string' },
      'skip-permissions': { type: 'boolean', default: false },
      description: { type: 'string' },
      memory: { type: 'boolean', default: false },
      model: { type: 'string' },
      effort: { type: 'string' },
    },
    strict: false,
  });
  rejectPositionals(positionals);
  return {
    name: values.name as string,
    cron: values.cron as string,
    command: values.command as string,
    workingDirectory: values['working-directory'] as string,
    timeout: values.timeout ? parseInt(values.timeout as string, 10) : undefined,
    skipPermissions: isFlagSet(values['skip-permissions']),
    description: values.description as string | undefined,
    memory: isFlagSet(values.memory),
    model: values.model as string | undefined,
    effort: values.effort as string | undefined,
  };
}

export function parseUpdateArgs(args: string[]): UpdateArgs {
  const { values, positionals } = parseArgs({
    args,
    options: {
      id: { type: 'string' },
      cron: { type: 'string' },
      command: { type: 'string' },
      timeout: { type: 'string' },
      enabled: { type: 'string' },
      name: { type: 'string' },
      description: { type: 'string' },
      memory: { type: 'string' },
      model: { type: 'string' },
      effort: { type: 'string' },
      'clear-model': { type: 'boolean', default: false },
      'clear-effort': { type: 'boolean', default: false },
    },
    strict: false,
  });
  rejectPositionals(positionals);
  return {
    id: values.id as string,
    cron: values.cron as string | undefined,
    command: values.command as string | undefined,
    timeout: values.timeout ? parseInt(values.timeout as string, 10) : undefined,
    enabled: values.enabled !== undefined ? values.enabled === 'true' : undefined,
    name: values.name as string | undefined,
    description: values.description as string | undefined,
    memory: values.memory !== undefined ? values.memory === 'true' : undefined,
    model: values.model as string | undefined,
    effort: values.effort as string | undefined,
    clearModel: isFlagSet(values['clear-model']),
    clearEffort: isFlagSet(values['clear-effort']),
  };
}
