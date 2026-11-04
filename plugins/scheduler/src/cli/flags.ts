import { parseArgs } from 'node:util';
import type { AddArgs } from './commands/add.js';

export function isFlagSet(value: string | boolean | undefined): boolean {
  return value === true || value === 'true';
}

export function parseAddArgs(args: string[]): AddArgs {
  const { values } = parseArgs({
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
