/**
 * Tests for the defensive coercion helpers.
 *
 * These exist so the formatter/transport hot paths can call .replace() on a
 * value that the type system claims is a string but at runtime may not be.
 * The key regression: safeToString must NEVER return a non-string (JSON.stringify
 * returns undefined for some inputs), or safeReplace would crash on .replace().
 */

// These tests deliberately pass `undefined` and use `toJSON: () => undefined`
// to reproduce the exact inputs that broke the helpers — the explicit undefined
// is the point, so disable the rule that wants it removed.
/* eslint-disable unicorn/no-useless-undefined */

import { safeReplace, safeToString } from '../coerce.utils';

describe('safeToString', () => {
  it('returns strings unchanged', () => {
    expect(safeToString('hello')).toBe('hello');
    expect(safeToString('')).toBe('');
  });

  it('maps null and undefined to an empty string', () => {
    expect(safeToString(null)).toBe('');
    expect(safeToString(undefined)).toBe('');
  });

  it('uses error.message for Error values', () => {
    expect(safeToString(new Error('boom'))).toBe('boom');
  });

  it('stringifies numbers, bigints, and booleans', () => {
    expect(safeToString(42)).toBe('42');
    expect(safeToString(10n)).toBe('10');
    expect(safeToString(true)).toBe('true');
  });

  it('describes symbols and functions without throwing', () => {
    expect(safeToString(Symbol('s'))).toContain('Symbol');
    expect(safeToString(function named() {})).toBe('[Function: named]');
    expect(safeToString(() => {})).toContain('[Function:');
  });

  it('JSON-stringifies plain objects and arrays', () => {
    expect(safeToString({ a: 1 })).toBe('{"a":1}');
    expect(safeToString([1, 2])).toBe('[1,2]');
  });

  it('never returns undefined when JSON.stringify yields undefined', () => {
    // An object whose toJSON returns undefined makes JSON.stringify return
    // undefined — the helper must fall back to a tag string instead.
    const result = safeToString({ toJSON: () => undefined });
    expect(typeof result).toBe('string');
    expect(result).toBe('[Object]');
  });

  it('falls back to a constructor tag for circular references', () => {
    const circular: Record<string, unknown> = {};
    circular.self = circular;
    const result = safeToString(circular);
    expect(typeof result).toBe('string');
    expect(result).toBe('[Object]');
  });
});

describe('safeReplace', () => {
  it('replaces on a normal string', () => {
    expect(safeReplace('Bearer abc', /Bearer\s+\S+/, '[REDACTED]')).toBe('[REDACTED]');
  });

  it('does not throw on a value whose JSON.stringify is undefined', () => {
    expect(() => safeReplace({ toJSON: () => undefined }, /x/, 'y')).not.toThrow();
    expect(safeReplace({ toJSON: () => undefined }, /Object/, 'Thing')).toBe('[Thing]');
  });

  it('coerces non-strings before replacing', () => {
    expect(safeReplace(12345, /\d+/, 'N')).toBe('N');
    expect(safeReplace(null, /x/, 'y')).toBe('');
  });
});
