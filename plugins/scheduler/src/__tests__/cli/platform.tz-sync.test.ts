/**
 * Tests for the macOS tz-sync launchd job installed alongside timezone-aware tasks.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createTask } from '../../index.js';

vi.mock('node:fs/promises', () => ({
  default: { readFile: vi.fn(), unlink: vi.fn(), writeFile: vi.fn() },
}));

vi.mock('../../utils/exec.js', () => ({
  exec: vi.fn(),
}));

vi.mock('../../utils/atomic.js', () => ({
  writeFileAtomic: vi.fn(),
}));

vi.mock('../../cli/commands/init.js', () => ({
  getCliShimPath: vi.fn(() => '/fake/bin/claude-scheduler-cli'),
}));

vi.mock('../../config.js', async () => {
  const actual = await vi.importActual<typeof import('../../config.js')>('../../config.js');
  return { ...actual, getLogsDir: vi.fn(() => '/fake/logs') };
});

import fs from 'node:fs/promises';
import { registerTask } from '../../cli/platform.js';
import { exec } from '../../utils/exec.js';
import { writeFileAtomic } from '../../utils/atomic.js';

const TZ_SYNC_LABEL = 'com.claude-scheduler.tz-sync';
const originalPlatform = process.platform;

const task = createTask({
  name: 'example-task',
  trigger: { type: 'cron', expression: '0 7 * * *', timezone: 'Europe/Paris' },
  execution: { command: 'echo hi', workingDirectory: '/tmp' },
});

function launchctlCalls(): string[][] {
  return vi.mocked(exec).mock.calls
    .filter(([cmd]) => cmd === 'launchctl')
    .map(([, args]) => args);
}

function tzSyncCalls(): string[][] {
  return launchctlCalls().filter(args => args.some(a => a.includes(TZ_SYNC_LABEL)));
}

function tzSyncWrites(): unknown[][] {
  return vi.mocked(writeFileAtomic).mock.calls.filter(([p]) => p.includes(TZ_SYNC_LABEL));
}

function tzSyncPlistWritten(): string {
  const [, content] = tzSyncWrites()[0] as [string, string];
  return content;
}

describe('registerTask on darwin: tz-sync job', () => {
  beforeEach(() => {
    Object.defineProperty(process, 'platform', { value: 'darwin' });
    vi.mocked(exec).mockResolvedValue({ stdout: '', stderr: '', exitCode: 0 });
    vi.mocked(writeFileAtomic).mockResolvedValue(undefined);
    vi.mocked(fs.readFile).mockRejectedValue(Object.assign(new Error('ENOENT'), { code: 'ENOENT' }));
    vi.stubEnv('XPC_SERVICE_NAME', '0');
  });

  afterEach(() => {
    Object.defineProperty(process, 'platform', { value: originalPlatform });
    vi.unstubAllEnvs();
  });

  it('installs and loads the job when it does not exist yet', async () => {
    await registerTask(task, '/fake/shim');

    const writes = tzSyncWrites();
    expect(writes).toHaveLength(1);
    expect(tzSyncPlistWritten()).toContain(`<string>${TZ_SYNC_LABEL}</string>`);
    expect(tzSyncPlistWritten()).toContain('<string>/fake/bin/claude-scheduler-cli</string>');
    expect(tzSyncCalls().map(args => args[0])).toEqual(['unload', 'load']);
  });

  it('reloads the job when its plist content changed', async () => {
    vi.mocked(fs.readFile).mockResolvedValue('<plist>old</plist>');

    await registerTask(task, '/fake/shim');

    expect(tzSyncWrites()).toHaveLength(1);
    expect(tzSyncCalls().map(args => args[0])).toEqual(['unload', 'load']);
  });

  it('leaves the job alone when its plist is unchanged and it is loaded', async () => {
    await registerTask(task, '/fake/shim');
    const plist = tzSyncPlistWritten();
    vi.mocked(exec).mockClear();
    vi.mocked(writeFileAtomic).mockClear();
    vi.mocked(fs.readFile).mockResolvedValue(plist);

    await registerTask(task, '/fake/shim');

    expect(tzSyncWrites()).toHaveLength(0);
    expect(tzSyncCalls()).toEqual([['list', TZ_SYNC_LABEL]]);
  });

  it('loads the job when its plist is unchanged but it is not loaded', async () => {
    await registerTask(task, '/fake/shim');
    const plist = tzSyncPlistWritten();
    vi.mocked(exec).mockClear();
    vi.mocked(writeFileAtomic).mockClear();
    vi.mocked(fs.readFile).mockResolvedValue(plist);
    vi.mocked(exec).mockImplementation(async (_cmd, args) => {
      if (args[0] === 'list') throw new Error('Could not find service');
      return { stdout: '', stderr: '', exitCode: 0 };
    });

    await registerTask(task, '/fake/shim');

    expect(tzSyncWrites()).toHaveLength(1);
    expect(tzSyncCalls().map(args => args[0])).toEqual(['list', 'unload', 'load']);
  });

  it('never touches the job from inside the tz-sync job itself', async () => {
    vi.stubEnv('XPC_SERVICE_NAME', TZ_SYNC_LABEL);
    vi.mocked(fs.readFile).mockResolvedValue('<plist>old</plist>');

    await registerTask(task, '/fake/shim');

    expect(tzSyncCalls()).toEqual([]);
    expect(tzSyncWrites()).toHaveLength(0);
    expect(launchctlCalls().map(args => args[0])).toEqual(['unload', 'load']);
  });

  it('leaves a plist change seen inside the job for the next registration to apply', async () => {
    const files = new Map<string, string>();
    vi.mocked(writeFileAtomic).mockImplementation(async (p, content) => {
      files.set(p, content);
    });
    vi.mocked(fs.readFile).mockImplementation((async (p: string) => files.get(p) ?? '<plist>old</plist>') as never);

    vi.stubEnv('XPC_SERVICE_NAME', TZ_SYNC_LABEL);
    await registerTask(task, '/fake/shim');
    vi.stubEnv('XPC_SERVICE_NAME', '0');
    vi.mocked(exec).mockClear();
    await registerTask(task, '/fake/shim');

    expect(tzSyncCalls().map(args => args[0])).toEqual(['unload', 'load']);
  });

  it('does not touch the job for a task in local time', async () => {
    const localTask = createTask({
      name: 'example-local-task',
      trigger: { type: 'cron', expression: '0 7 * * *', timezone: 'local' },
      execution: { command: 'echo hi', workingDirectory: '/tmp' },
    });

    await registerTask(localTask, '/fake/shim');

    expect(tzSyncCalls()).toEqual([]);
    expect(tzSyncWrites()).toHaveLength(0);
  });
});
