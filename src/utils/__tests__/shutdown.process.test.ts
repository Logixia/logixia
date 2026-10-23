import { spawn } from 'child_process';
import path from 'path';

const fixture = path.resolve(__dirname, '../../../test/fixtures/shutdown-app.ts');
const tsNode = require.resolve('ts-node/register/transpile-only');

interface RunResult {
  stdout: string;
  code: number | null;
  signal: NodeJS.Signals | null;
}

function run(mode: string, signalToSend?: NodeJS.Signals): Promise<RunResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ['-r', tsNode, fixture, mode], {
      env: { ...process.env, TS_NODE_COMPILER_OPTIONS: '{"module":"commonjs"}' },
    });
    let stdout = '';
    let signalled = false;
    child.stdout.on('data', (chunk: Buffer) => {
      stdout += chunk.toString();
      if (signalToSend && !signalled && stdout.includes('ready')) {
        signalled = true;
        child.kill(signalToSend);
      }
    });
    child.on('error', reject);
    child.on('close', (code, signal) => resolve({ stdout, code, signal }));
  });
}

describe('flushOnExit in a real process', () => {
  jest.setTimeout(30_000);

  it('lets the app finish its own SIGTERM cleanup when it has a handler', async () => {
    const result = await run('own-handler', 'SIGTERM');
    expect(result.stdout).toContain('logger-closed');
    expect(result.stdout).toContain('app-cleanup-done');
    expect(result.code).toBe(0);
  });

  it('exits with 128 + signal when logixia is the only SIGTERM listener', async () => {
    const result = await run('sole-handler', 'SIGTERM');
    expect(result.stdout).toContain('logger-closed');
    expect(result.code).toBe(143);
  });

  it('flushes without closing registered loggers on a normal exit', async () => {
    const result = await run('natural-exit');
    expect(result.stdout).toContain('logger-flushed');
    expect(result.stdout).not.toContain('logger-closed');
    expect(result.code).toBe(0);
  });
});
