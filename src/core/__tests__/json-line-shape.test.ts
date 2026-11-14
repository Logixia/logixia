/**
 * A JSON line keeps a fixed shape for log pipelines: the entry's fixed fields are
 * strings, the payload is an object, and the payload comes last.
 */

import type { LogEntry } from '../../types';
import { resetShutdownHandlers } from '../../utils/shutdown.utils';
import { createLogger } from '../logitron-logger';

function captureStdout(): { lines: string[]; restore(): void } {
  const lines: string[] = [];
  const original = process.stdout.write.bind(process.stdout);
  (process.stdout as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };
  return {
    lines,
    restore: () => {
      (process.stdout as NodeJS.WriteStream).write = original as typeof process.stdout.write;
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
  const cap = captureStdout();
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

  it('escapes quotes, control characters and lone surrogates', async () => {
    const message = 'q"\\\n\u0000 \ud800';
    const { raw, parsed } = await jsonLine((l) => l.info(message));
    expect(parsed.message).toBe(message);
    expect(raw).not.toContain('\n');
  });
});
