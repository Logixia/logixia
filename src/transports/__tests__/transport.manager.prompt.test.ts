import * as readline from 'node:readline';

import type { LogEntry } from '../../types';
import { internalWarn } from '../../utils/internal-log';
import { TransportManager } from '../transport.manager';

jest.mock('node:readline', () => ({ createInterface: jest.fn() }));
jest.mock('../../utils/internal-log', () => ({
  ...jest.requireActual('../../utils/internal-log'),
  internalWarn: jest.fn(),
}));

const entry: LogEntry = {
  timestamp: new Date('2026-01-01T00:00:00.000Z').toISOString(),
  level: 'info',
  appName: 'test-app',
  message: 'hello',
};

describe('TransportManager never prompts', () => {
  const createInterface = readline.createInterface as unknown as jest.Mock;
  let stdoutWrite: jest.SpyInstance;
  let stdinOn: jest.SpyInstance;

  beforeEach(() => {
    (internalWarn as jest.Mock).mockClear();
    createInterface.mockClear();
    stdoutWrite = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    stdinOn = jest.spyOn(process.stdin, 'on');
  });

  afterEach(() => {
    jest.restoreAllMocks();
  });

  it('enableLevelPrompting() is a no-op that warns once', async () => {
    const manager = new TransportManager({ console: { level: 'info' } });
    manager.enableLevelPrompting();
    manager.enableLevelPrompting();
    manager.disableLevelPrompting();

    await manager.write(entry);

    expect(createInterface).not.toHaveBeenCalled();
    expect(stdinOn).not.toHaveBeenCalled();
    expect(internalWarn).toHaveBeenCalledTimes(1);
    expect(internalWarn).toHaveBeenCalledWith(expect.stringContaining('setTransportLevels'));
    await manager.close();
  });

  it('keeps writing synchronously after enableLevelPrompting()', async () => {
    const manager = new TransportManager({ console: { level: 'info' } });
    manager.enableLevelPrompting();
    const written: string[] = [];
    manager.on('error', (e: Error) => written.push(e.message));

    const result = manager.write(entry);

    expect(result).toBeUndefined();
    expect(written).toEqual([]);
    await manager.close();
  });

  it('exposes no interactive prompt methods', () => {
    const manager = new TransportManager({});
    const methods = manager as unknown as Record<string, unknown>;
    expect(methods.promptUserForTransportLevels).toBeUndefined();
    expect(methods.configureTransportLevels).toBeUndefined();
    expect(stdoutWrite).not.toHaveBeenCalledWith(expect.stringContaining('Configure log levels'));
  });
});
