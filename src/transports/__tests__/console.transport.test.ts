/**
 * Tests for ConsoleTransport
 *
 * Covers the documented contract:
 *  - "compact JSON mode" (one line per entry — line-based collectors)
 *  - CWE-117 control-char stripping applied to ALL user-controlled text in text
 *    mode, including the (possibly custom) level name
 *  - stdout/stderr routing
 */

import type { TransportLogEntry } from '../../types/transport.types';
import { ConsoleTransport } from '../console.transport';

function makeEntry(overrides: Partial<TransportLogEntry> = {}): TransportLogEntry {
  return {
    timestamp: new Date('2026-01-01T00:00:00.000Z'),
    level: 'info',
    message: 'hello',
    appName: 'TestApp',
    environment: 'test',
    ...overrides,
  };
}

function capture(): {
  out: string[];
  err: string[];
  restore: () => void;
} {
  const out: string[] = [];
  const err: string[] = [];
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  (process.stdout as NodeJS.WriteStream).write = (chunk: unknown) => {
    out.push(String(chunk ?? ''));
    return true;
  };
  (process.stderr as NodeJS.WriteStream).write = (chunk: unknown) => {
    err.push(String(chunk ?? ''));
    return true;
  };
  return {
    out,
    err,
    restore() {
      (process.stdout as NodeJS.WriteStream).write = origOut as typeof process.stdout.write;
      (process.stderr as NodeJS.WriteStream).write = origErr as typeof process.stderr.write;
    },
  };
}

describe('ConsoleTransport — JSON mode', () => {
  it('emits compact single-line JSON (no pretty-print newlines)', async () => {
    const cap = capture();
    const t = new ConsoleTransport({ format: 'json', colorize: false });
    await t.write(makeEntry({ data: { a: 1, b: 2 } }));
    cap.restore();

    const line = cap.out.join('');
    // One trailing newline only — the JSON body itself must not contain newlines.
    const body = line.replace(/\n$/, '');
    expect(body.includes('\n')).toBe(false);
    // Still valid JSON.
    const parsed = JSON.parse(body);
    expect(parsed.message).toBe('hello');
    expect(parsed.a).toBe(1);
  });
});

describe('ConsoleTransport — CWE-117 sanitization', () => {
  it('strips control characters from a custom level name in text mode', async () => {
    const cap = capture();
    const t = new ConsoleTransport({ format: 'text', colorize: false });
    // A custom level carrying an ANSI escape — must not reach the terminal raw.
    await t.write(makeEntry({ level: 'kafka\x1b[31m\x07' }));
    cap.restore();

    const line = cap.out.join('');
    expect(line).not.toContain('\x1b[31m');
    expect(line).not.toContain('\x07');
    expect(line).toContain('KAFKA');
  });
});

describe('ConsoleTransport — stream routing', () => {
  it('writes error entries to stderr', async () => {
    const cap = capture();
    const t = new ConsoleTransport({ format: 'text', colorize: false });
    await t.write(makeEntry({ level: 'error', message: 'boom' }));
    cap.restore();
    expect(cap.err.join('')).toContain('boom');
    expect(cap.out.join('')).toBe('');
  });

  it('writes warn entries to stderr (documented: stderr handles error/warn)', async () => {
    const cap = capture();
    const t = new ConsoleTransport({ format: 'text', colorize: false });
    await t.write(makeEntry({ level: 'warn', message: 'careful' }));
    cap.restore();
    expect(cap.err.join('')).toContain('careful');
    expect(cap.out.join('')).toBe('');
  });

  it('writes info entries to stdout', async () => {
    const cap = capture();
    const t = new ConsoleTransport({ format: 'text', colorize: false });
    await t.write(makeEntry({ level: 'info', message: 'fyi' }));
    cap.restore();
    expect(cap.out.join('')).toContain('fyi');
    expect(cap.err.join('')).toBe('');
  });
});
