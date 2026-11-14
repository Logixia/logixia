/**
 * A JSON line keeps a fixed shape for log pipelines: the entry's fixed fields are
 * strings, the payload is an object, and the payload comes last.
 */

import type { LogEntry } from '../../types';
import { resetShutdownHandlers } from '../../utils/shutdown.utils';
import { createLogger } from '../logixia-logger';

// Error lines go to stderr, everything else to stdout.
function captureOutput(): { lines: string[]; restore(): void } {
  const lines: string[] = [];
  const out = process.stdout.write.bind(process.stdout);
  const err = process.stderr.write.bind(process.stderr);
  const capture = (chunk: unknown): boolean => {
    lines.push(String(chunk ?? ''));
    return true;
  };
  (process.stdout as NodeJS.WriteStream).write = capture as typeof process.stdout.write;
  (process.stderr as NodeJS.WriteStream).write = capture as typeof process.stderr.write;
  return {
    lines,
    restore: () => {
      (process.stdout as NodeJS.WriteStream).write = out as typeof process.stdout.write;
      (process.stderr as NodeJS.WriteStream).write = err as typeof process.stderr.write;
    },
  };
}

async function jsonLine(
  log: (logger: ReturnType<typeof createLogger>) => Promise<void>,
  rewrite?: (entry: LogEntry) => LogEntry
): Promise<{ raw: string; parsed: Record<string, unknown> }> {
  const logger = createLogger(
    { appName: 'app', environment: 'test', format: { json: true }, traceId: true },
    'orders'
  );
  if (rewrite) logger.use({ name: 'rewrite', onLog: rewrite });
  const cap = captureOutput();
  try {
    await log(logger);
  } finally {
    cap.restore();
  }
  const raw = cap.lines.join('').trim();
  return { raw, parsed: JSON.parse(raw) as Record<string, unknown> };
}

beforeEach(() => resetShutdownHandlers());
afterEach(() => resetShutdownHandlers());

describe('JSON line shape', () => {
  it('writes the fixed fields in order, with the payload last', async () => {
    const { parsed } = await jsonLine((l) => l.info('placed', { orderId: 'o1' }));
    expect(Object.keys(parsed)).toEqual([
      'timestamp',
      'level',
      'appName',
      'environment',
      'message',
      'context',
      'traceId',
      'payload',
    ]);
    expect(parsed.payload).toEqual({ orderId: 'o1' });
  });

  it('writes non-string fixed fields as strings', async () => {
    const { parsed } = await jsonLine(
      (l) => l.info('m'),
      (entry) => ({ ...entry, message: 42, context: null, traceId: true }) as unknown as LogEntry
    );
    expect(parsed).toMatchObject({ message: '42', context: '', traceId: 'true' });
  });

  it('writes an array or null payload as an object', async () => {
    const arr = await jsonLine((l) =>
      l.info('m', ['a', 'b'] as unknown as Record<string, unknown>)
    );
    expect(arr.parsed.payload).toEqual({ 0: 'a', 1: 'b' });
    const nil = await jsonLine(
      (l) => l.info('m'),
      (entry) => ({ ...entry, payload: null }) as unknown as LogEntry
    );
    expect(nil.parsed.payload).toEqual({});
  });

  it('uses toJSON for a payload that has one, such as a Date', async () => {
    const { parsed } = await jsonLine((l) =>
      l.info('m', new Date(0) as unknown as Record<string, unknown>)
    );
    expect(parsed.payload).toBe('1970-01-01T00:00:00.000Z');
  });

  it('writes the same line on the cached fast path as on the general path', async () => {
    const boom = new TypeError('boom');
    const calls: Array<(logger: ReturnType<typeof createLogger>) => Promise<void>> = [
      (l) => l.info('plain'),
      (l) => l.info('q"\\\n\u0000 \ud800 \u2028', { nested: { list: [1, 'two', null] }, n: 1.5 }),
      (l) => l.warn('with data', { at: new Date(0), skip: undefined }),
      (l) => l.error(boom),
      (l) => l.child('kid').info('from a child', { k: 'v' }),
    ];
    for (const call of calls) {
      const fast = await jsonLine(call);
      // A plugin that changes nothing sends the entry down the general path.
      const general = await jsonLine(call, (entry) => entry);
      const normalize = (line: string): string =>
        line
          .replace(/"timestamp":"[^"]*"/, '"timestamp":""')
          .replace(/"traceId":"[^"]*"/, '"traceId":""');
      expect(normalize(fast.raw)).toBe(normalize(general.raw));
    }
  });

  it('escapes quotes, control characters and lone surrogates', async () => {
    const message = 'q"\\\n\u0000 \ud800';
    const { raw, parsed } = await jsonLine((l) => l.info(message));
    expect(parsed.message).toBe(message);
    expect(raw).not.toContain('\n');
  });
});
