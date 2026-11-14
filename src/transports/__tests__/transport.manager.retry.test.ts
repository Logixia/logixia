import type { LogEntry } from '../../types';
import type { ITransport, TransportLogEntry } from '../../types/transport.types';
import { TransportManager } from '../transport.manager';

const entry = (i = 0): LogEntry =>
  ({ timestamp: new Date(), level: 'info', message: `m${i}`, appName: 'a' }) as LogEntry;

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function makeManager(transport: ITransport) {
  const manager = new TransportManager({ custom: [transport] });
  manager.on('error', () => {});
  return manager;
}

beforeEach(() => {
  process.env['LOGIXIA_SILENT_INTERNAL'] = '1';
});

describe('TransportManager retry queue', () => {
  it('does not hold the caller across backoff', async () => {
    const transport: ITransport = {
      name: 'down',
      write: async () => {
        throw new Error('down');
      },
      retry: { maxRetries: 3, delay: 500 },
    };
    const manager = makeManager(transport);
    const start = Date.now();
    await manager.write(entry());
    expect(Date.now() - start).toBeLessThan(200);
    await manager.close();
  });

  it('retries in the background until the transport recovers', async () => {
    let calls = 0;
    const written: TransportLogEntry[] = [];
    const transport: ITransport = {
      name: 'flaky',
      write: async (e) => {
        if (++calls < 3) throw new Error('flaky');
        written.push(e);
      },
      retry: { maxRetries: 5, backoff: 'fixed', delay: 10 },
    };
    const manager = makeManager(transport);
    await manager.write(entry(1));
    expect(written).toHaveLength(0);
    await sleep(150);
    expect(written.map((e) => e.message)).toEqual(['m1']);
    await manager.close();
  });

  it('sends to the fallback and calls onExhausted after the last retry', async () => {
    const fallback: TransportLogEntry[] = [];
    const exhausted: string[] = [];
    const transport: ITransport = {
      name: 'dead',
      write: async () => {
        throw new Error('dead');
      },
      retry: {
        maxRetries: 2,
        backoff: 'fixed',
        delay: 5,
        fallback: { name: 'fb', write: (e) => void fallback.push(e) },
        onExhausted: (_e, en) => void exhausted.push(en.message),
      },
    };
    const manager = makeManager(transport);
    await manager.write(entry(7));
    await sleep(100);
    expect(fallback.map((e) => e.message)).toEqual(['m7']);
    expect(exhausted).toEqual([]);
    await manager.close();
  });

  it('caps pending retries and drops the oldest', async () => {
    let attempts = 0;
    const transport: ITransport = {
      name: 'dead',
      write: async () => {
        attempts++;
        throw new Error('dead');
      },
      retry: { maxRetries: 5, delay: 60_000, maxPending: 10 },
    };
    const manager = makeManager(transport);
    for (let i = 0; i < 500; i++) manager.write(entry(i));
    await sleep(20);
    const state = (manager as unknown as { retryStates: Map<string, { queue: unknown[] }> })
      .retryStates;
    expect([...state.values()][0]!.queue.length).toBeLessThanOrEqual(10);
    expect(attempts).toBe(500);
    await manager.close();
  });

  it('reports a failing close() from removeTransport without an unhandled error event', async () => {
    const transport: ITransport = {
      name: 'bad-close',
      write: () => {},
      close: async () => {
        throw new Error('close failed');
      },
    };
    const manager = new TransportManager({ custom: [transport] });
    expect(manager.removeTransport('custom-0')).toBe(true);
    await sleep(10);
  });
});

describe('TransportManager after close', () => {
  it('writes late log lines to stdout/stderr instead of dropping them', async () => {
    const manager = new TransportManager({ custom: [{ name: 'mem', write: () => {} }] });
    await manager.close();
    const out = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const err = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    try {
      manager.write(entry(1));
      manager.write({ ...entry(2), level: 'error' });
      expect(String(out.mock.calls[0]?.[0])).toContain('"message":"m1"');
      expect(String(err.mock.calls[0]?.[0])).toContain('"message":"m2"');
    } finally {
      out.mockRestore();
      err.mockRestore();
    }
  });

  it('closes each transport once when close() is called concurrently', async () => {
    const close = jest.fn(async () => {});
    const manager = new TransportManager({ custom: [{ name: 'mem', write: () => {}, close }] });
    await Promise.all([manager.close(), manager.close()]);
    expect(close).toHaveBeenCalledTimes(1);
  });
});
