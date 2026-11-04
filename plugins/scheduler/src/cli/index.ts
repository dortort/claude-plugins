/**
 * CLI entry point for claude-scheduler.
 * Invoked by skills as: node ./dist/cli/index.js <subcommand> [args]
 * Uses Node 18+ built-in util.parseArgs (no external dependencies).
 */

import { parseArgs } from 'node:util';
import { init } from './commands/init.js';
import { sync } from './commands/sync.js';
import { parseAddArgs, parseUpdateArgs } from './flags.js';

async function main() {
  const args = process.argv.slice(2);
  const subcommand = args[0];

  if (!subcommand) {
    console.error('Usage: claude-scheduler <subcommand> [options]');
    console.error('Subcommands: init, sync, add, remove, update, migrate, validate-schedule, humanize');
    process.exit(1);
  }

  try {
    switch (subcommand) {
      case 'init': {
        const result = await init();
        console.log(JSON.stringify(result));
        process.exitCode = result.success ? 0 : 1;
        break;
      }

      case 'sync': {
        const { values } = parseArgs({
          args: args.slice(1),
          options: {
            id: { type: 'string' },
            config: { type: 'string' },
          },
          strict: false,
        });

        // Dynamic import to avoid loading platform code eagerly
        const { registerTask } = await import('./platform.js');
        const result = await sync(registerTask, {
          taskId: values.id as string | undefined,
          configPath: values.config as string | undefined,
        });
        console.log(JSON.stringify(result));
        process.exitCode = result.success ? 0 : 1;
        break;
      }

      case 'add': {
        const { add } = await import('./commands/add.js');
        const result = await add(parseAddArgs(args.slice(1)));
        console.log(JSON.stringify(result));
        process.exitCode = result.success ? 0 : 1;
        break;
      }

      case 'remove': {
        const { remove } = await import('./commands/remove.js');
        const { values } = parseArgs({
          args: args.slice(1),
          options: {
            id: { type: 'string' },
          },
          strict: false,
        });
        const result = await remove({ id: values.id as string });
        console.log(JSON.stringify(result));
        process.exitCode = result.success ? 0 : 1;
        break;
      }

      case 'update': {
        const { update } = await import('./commands/update.js');
        const result = await update(parseUpdateArgs(args.slice(1)));
        console.log(JSON.stringify(result));
        process.exitCode = result.success ? 0 : 1;
        break;
      }

      case 'migrate': {
        const { migrate } = await import('./commands/migrate.js');
        const result = await migrate();
        console.log(JSON.stringify(result));
        process.exitCode = result.success ? 0 : 1;
        break;
      }

      case 'validate-schedule': {
        const { validateSchedule } = await import('./commands/validate-schedule.js');
        const { values } = parseArgs({
          args: args.slice(1),
          options: {
            input: { type: 'string' },
          },
          strict: false,
        });
        if (!values.input) {
          console.error(JSON.stringify({ error: 'Missing --input flag' }));
          process.exit(1);
        }
        const result = validateSchedule(values.input as string);
        console.log(JSON.stringify(result));
        process.exitCode = 'error' in result ? 1 : 0;
        break;
      }

      case 'humanize': {
        const { humanize } = await import('./commands/humanize.js');
        const { values } = parseArgs({
          args: args.slice(1),
          options: {
            tasks: { type: 'string' },
          },
          strict: false,
        });
        if (!values.tasks) {
          console.error(JSON.stringify({ error: 'Missing --tasks flag' }));
          process.exit(1);
        }
        const tasks = JSON.parse(values.tasks as string);
        const result = humanize(tasks);
        console.log(JSON.stringify(result));
        break;
      }

      default:
        console.error(`Unknown subcommand: ${subcommand}`);
        process.exit(1);
    }
  } catch (err) {
    console.error(JSON.stringify({ success: false, error: (err as Error).message }));
    process.exit(1);
  }
}

main();
