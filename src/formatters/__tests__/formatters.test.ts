/**
 * Tests for the JSON and text formatters.
 *
 * Key regression: a payload containing a circular reference (e.g. an Express
 * req/res, a DB connection, a Mongoose document) must NOT crash format() — both
 * formatters previously called raw JSON.stringify and threw "Converting circular
 * structure to JSON", taking down the whole log/transport path.
 */

import type { LogEntry } from '../../types';
import { JsonFormatter } from '../json.formatter';
import { TextFormatter } from '../text.formatter';

function baseEntry(overrides: Partial<LogEntry> = {}): LogEntry {
  return {
    timestamp: '2026-01-01T00:00:00.000Z',
    level: 'info',
    appName: 'TestApp',
    message: 'hello',
    ...overrides,
  };
}

function makeCircular(): Record<string, unknown> {
  const obj: Record<string, unknown> = { name: 'req' };
  obj.self = obj;
  return obj;
}

describe('JsonFormatter', () => {
  it('produces valid JSON for a normal entry', () => {
    const out = new JsonFormatter().format(baseEntry({ payload: { userId: 'u1' } }));
    const parsed = JSON.parse(out);
    expect(parsed.message).toBe('hello');
    expect(parsed.payload.userId).toBe('u1');
  });

  it('does not crash on a circular payload and still emits valid JSON', () => {
    const formatter = new JsonFormatter();
    let out = '';
    expect(() => {
      out = formatter.format(baseEntry({ payload: { req: makeCircular() } }));
    }).not.toThrow();

    const parsed = JSON.parse(out); // must be valid JSON
    expect(JSON.stringify(parsed)).toContain('[Circular]');
  });

  it('serializes an Error in the payload', () => {
    const out = new JsonFormatter().format(baseEntry({ payload: { err: new Error('boom') } }));
    const parsed = JSON.parse(out);
    expect(parsed.payload.err.message).toBe('boom');
  });
});

describe('TextFormatter', () => {
  it('formats a simple single-key payload as key=value', () => {
    const out = new TextFormatter({ colorize: false }).format(baseEntry({ payload: { count: 5 } }));
    expect(out).toContain('count=5');
  });

  it('does not crash on a circular payload', () => {
    const formatter = new TextFormatter({ colorize: false });
    expect(() =>
      formatter.format(baseEntry({ payload: { req: makeCircular(), other: 'val' } }))
    ).not.toThrow();
  });

  it('strips ASCII control characters from the message (CWE-117)', () => {
    // Build the message with explicit control-char codes (ESC + BEL) so an
    // attacker could otherwise smuggle an ANSI escape through the formatter.
    const esc = String.fromCharCode(0x1b);
    const bel = String.fromCharCode(0x07);
    const out = new TextFormatter({ colorize: false }).format(
      baseEntry({ message: `safe${esc}[31m${bel}Injected` })
    );
    expect(out).not.toContain(esc);
    expect(out).not.toContain(bel);
    expect(out).toContain('Injected');
  });
});
