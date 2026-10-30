/**
 * Runs a real worker thread against the built dist/worker-entry.js.
 * Skipped when dist is missing; CI runs the build job's check:exports as well.
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import type { TransportLogEntry } from '../../types/transport.types';
import { WorkerTransport } from '../worker.transport';

const workerEntry = path.resolve(__dirname, '../../../dist/worker-entry.js');
const describeBuilt = fs.existsSync(workerEntry) ? describe : describe.skip;

class BuiltWorkerTransport extends WorkerTransport {
  protected override workerFile(): string {
    return workerEntry;
  }
}

function entry(message: string): TransportLogEntry {
  return {
    timestamp: new Date(),
    level: 'info',
    message,
    data: {},
  };
}

describeBuilt('WorkerTransport with a real worker', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-worker-'));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('writes entries to a file and flushes them on close', async () => {
    const transport = new BuiltWorkerTransport({
      transportType: 'file',
      transportConfig: { filename: 'app.log', dirname: dir },
    });
    const total = 50;
    for (let i = 0; i < total; i++) transport.write(entry(`message-${i}`));
    await transport.close();

    const written = fs
      .readdirSync(dir)
      .map((name) => fs.readFileSync(path.join(dir, name), 'utf8'))
      .join('');
    for (let i = 0; i < total; i++) expect(written).toContain(`message-${i}`);
    expect(written.indexOf('message-0')).toBeLessThan(written.indexOf('message-49'));
  });

  it('applies the wrapped transport level inside the worker', async () => {
    const transport = new BuiltWorkerTransport({
      transportType: 'file',
      transportConfig: { filename: 'lvl.log', dirname: dir, level: 'error' },
    });
    transport.write({ ...entry('keep-me'), level: 'error' });
    transport.write(entry('drop-me'));
    await transport.close();

    const written = fs
      .readdirSync(dir)
      .map((name) => fs.readFileSync(path.join(dir, name), 'utf8'))
      .join('');
    expect(written).toContain('keep-me');
    expect(written).not.toContain('drop-me');
  });
});
