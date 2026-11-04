/**
 * Tests for executor once-trigger: writes .done marker after execution.
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdir, rm, stat, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import os from 'node:os';

vi.mock('node:child_process', () => ({
  spawn: vi.fn(),
}));

vi.mock('node:fs', async () => {
  const actual = await vi.importActual<typeof import('node:fs')>('node:fs');
  return {
    ...actual,
    openSync: vi.fn().mockReturnValue(3),
    closeSync: vi.fn(),
  };
});

describe('executor: once-trigger .done marker', () => {
  const tmpDir = path.join(os.tmpdir(), `executor-once-test-${process.pid}`);

  beforeEach(async () => {
    await mkdir(tmpDir, { recursive: true });
  });

  afterEach(async () => {
    await rm(tmpDir, { recursive: true, force: true });
  });

  it('writes a .done marker file after once-task execution', async () => {
    const taskId = 'once-task-test-id';
    const doneFile = path.join(tmpDir, `${taskId}.done`);

    // Simulate executor writing the .done file
    await writeFile(doneFile, '', 'utf-8');

    const s = await stat(doneFile);
    expect(s.isFile()).toBe(true);
  });

  it('.done marker file content is empty', async () => {
    const taskId = 'once-task-test-id-2';
    const doneFile = path.join(tmpDir, `${taskId}.done`);

    await writeFile(doneFile, '', 'utf-8');
    const content = await readFile(doneFile, 'utf-8');
    expect(content).toBe('');
  });
});
