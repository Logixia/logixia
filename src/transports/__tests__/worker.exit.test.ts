import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';

const fixture = path.resolve(__dirname, '../../../test/fixtures/worker-exit-app.ts');
const tsNode = require.resolve('ts-node/register/transpile-only');

describe('WorkerTransport process lifetime', () => {
  jest.setTimeout(30_000);

  it('lets the process exit by itself and still delivers pending lines', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-worker-exit-'));
    const out = path.join(dir, 'out.log');
    const code = await new Promise<number | null>((resolve, reject) => {
      const child = spawn(process.execPath, ['-r', tsNode, fixture], {
        env: {
          ...process.env,
          IDLE_WORKER_OUT: out,
          TS_NODE_COMPILER_OPTIONS: '{"module":"commonjs"}',
        },
      });
      const alarm = setTimeout(() => {
        child.kill('SIGKILL');
      }, 15_000);
      child.on('error', reject);
      child.on('close', (c) => {
        clearTimeout(alarm);
        resolve(c);
      });
    });
    expect(code).toBe(0);
    expect(fs.readFileSync(out, 'utf8').trim().split('\n')).toHaveLength(20);
    fs.rmSync(dir, { recursive: true, force: true });
  });
});
