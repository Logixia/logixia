/**
 * Tests for robust serialization (R9): BigInt, circular refs, deterministic key
 * order, and round-trippable $ref decycle/retrocycle.
 */

import { decycleValue, retrocycle, safeStringify } from '../safe-stringify';

describe('safeStringify', () => {
  it('serializes BigInt as a string by default (JSON.stringify would throw)', () => {
    expect(() => JSON.stringify({ id: 10n })).toThrow();
    expect(safeStringify({ id: 10n })).toBe('{"id":"10"}');
  });

  it('serializes BigInt as a number when requested', () => {
    expect(safeStringify({ id: 7n }, { bigint: 'number' })).toBe('{"id":7}');
  });

  it('replaces circular references with [Circular] (no throw)', () => {
    const obj: Record<string, unknown> = { a: 1 };
    obj.self = obj;
    const out = safeStringify(obj);
    expect(out).toContain('[Circular]');
    expect(JSON.parse(out)).toEqual({ a: 1, self: '[Circular]' });
  });

  it('allows the same object in sibling branches (not a false cycle)', () => {
    const shared = { x: 1 };
    const out = safeStringify({ a: shared, b: shared });
    // shared appears in both — neither should be [Circular] since it's not a cycle.
    expect(JSON.parse(out)).toEqual({ a: { x: 1 }, b: { x: 1 } });
  });

  it('produces deterministic key order when requested', () => {
    const a = safeStringify({ b: 1, a: 2, c: 3 }, { deterministic: true });
    const b = safeStringify({ c: 3, a: 2, b: 1 }, { deterministic: true });
    expect(a).toBe(b);
    expect(a).toBe('{"a":2,"b":1,"c":3}');
  });

  it('renders Dates, functions and symbols safely', () => {
    const out = JSON.parse(
      safeStringify({ d: new Date('2026-01-01T00:00:00.000Z'), f: () => 0, s: Symbol('z') })
    );
    expect(out.d).toBe('2026-01-01T00:00:00.000Z');
    expect(out.f).toContain('[Function');
    expect(out.s).toContain('Symbol');
  });

  it('ignores prototype-pollution keys', () => {
    const out = JSON.parse(safeStringify(JSON.parse('{"__proto__":{"x":1},"ok":2}')));
    expect(out.ok).toBe(2);
    expect(out.__proto__).not.toEqual({ x: 1 });
  });
});

describe('decycle / retrocycle round-trip', () => {
  it('emits $ref pointers for repeated references and round-trips them back', () => {
    const a: Record<string, unknown> = { name: 'A' };
    const b: Record<string, unknown> = { name: 'B', parent: a };
    a.child = b; // a → b → a (cycle)

    const json = safeStringify(a, { decycle: true });
    // The back-reference is a $ref pointer, not [Circular].
    expect(json).toContain('$ref');
    expect(json).not.toContain('[Circular]');

    const parsed = retrocycle(JSON.parse(json)) as Record<string, unknown>;
    expect(parsed.name).toBe('A');
    const childBack = parsed.child as Record<string, unknown>;
    expect(childBack.name).toBe('B');
    // The cycle is reconstructed: child.parent === root.
    expect(childBack.parent).toBe(parsed);
  });

  it('decycleValue handles BigInt inside a decycled graph', () => {
    const out = decycleValue({ big: 5n });
    expect(out).toEqual({ big: '5' });
  });

  it('round-trips shared (non-circular) references to the same object', () => {
    const shared = { v: 42 };
    const json = safeStringify({ p: shared, q: shared }, { decycle: true });
    const parsed = retrocycle(JSON.parse(json)) as { p: unknown; q: unknown };
    expect(parsed.p).toBe(parsed.q); // same reference restored
  });
});
