import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { TransportManager } from '../../transports/transport.manager';
import { _shutdownRegistrySize, resetShutdownHandlers } from '../../utils/shutdown.utils';
import { LogixiaLogger } from '../logitron-logger';

function makeLogger(filename: string, extra: Record<string, unknown> = {}) {
  return new LogixiaLogger({
    appName: 'ChildTest',
    environment: 'development',
    traceId: false,
    silent: false,
    format: { timestamp: false, colorize: false, json: false },
    transports: { file: { filename, dirname: path.dirname(filename), batchSize: 1000 } },
    ...extra,
  } as never);
}

function readLines(file: string): string[] {
  return fs
    .readFileSync(file, 'utf8')
    .split('\n')
    .filter((l) => l.trim().length > 0);
}

describe('child() shares the root transports', () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'logixia-child-'));
  });

  afterEach(() => {
    resetShutdownHandlers();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('writes every child line plus the parent line on root close', async () => {
    const file = path.join(dir, 'app.log');
    const logger = makeLogger(file);
    for (let i = 0; i < 20; i++) await logger.child(`req-${i}`).info('hi');
    await logger.info('parent');
    await logger.close();
    expect(readLines(file)).toHaveLength(21);
  });

  it('adds no timers across 1,000 child() calls that each log', async () => {
    const logger = makeLogger(path.join(dir, 'app.log'));
    const count = () => process.getActiveResourcesInfo().filter((r) => r === 'Timeout').length;
    const before = count();
    for (let i = 0; i < 1000; i++) await logger.child(`req-${i}`).info('hi');
    const during = count();
    await logger.close();
    expect(during - before).toBeLessThanOrEqual(2);
  });

  it('keeps the parent working after a child closes', async () => {
    const file = path.join(dir, 'app.log');
    const logger = makeLogger(file);
    const child = logger.child('req');
    await child.info('from child');
    const closeSpy = jest.spyOn(TransportManager.prototype, 'close');
    await child.close();
    expect(closeSpy).not.toHaveBeenCalled();
    closeSpy.mockRestore();
    await logger.info('from parent');
    await logger.close();
    const lines = readLines(file);
    expect(lines).toHaveLength(2);
    expect(lines[0]).toContain('from child');
    expect(lines[1]).toContain('from parent');
  });

  it('does not register children for graceful shutdown', async () => {
    const logger = makeLogger(path.join(dir, 'app.log'), { gracefulShutdown: true });
    const baseline = _shutdownRegistrySize();
    for (let i = 0; i < 50; i++) logger.child(`req-${i}`);
    expect(_shutdownRegistrySize()).toBe(baseline);
    await logger.close();
  });

  it('shares the plugin registry with the root', async () => {
    const file = path.join(dir, 'app.log');
    const logger = makeLogger(file);
    const child = logger.child('req');
    const seen: string[] = [];
    logger.use({
      name: 'spy',
      onLog(entry) {
        seen.push(String(entry.message));
        return entry;
      },
    });
    await child.info('via child');
    expect(seen).toEqual(['via child']);
    await logger.close();
  });
});
