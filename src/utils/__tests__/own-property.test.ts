import { setOwnProperty } from '../own-property';
import { safeStringify } from '../safe-stringify';

describe('setOwnProperty', () => {
  it('stores __proto__ as an own property without changing the prototype', () => {
    const target: Record<string, unknown> = {};
    setOwnProperty(target, '__proto__', { polluted: true });
    expect(Object.getPrototypeOf(target)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(target, '__proto__')).toBe(true);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });

  it('creates enumerable, writable data properties', () => {
    const target: Record<string, unknown> = {};
    setOwnProperty(target, 'a', 1);
    target['a'] = 2;
    expect(target).toEqual({ a: 2 });
    expect(Object.keys(target)).toEqual(['a']);
  });
});

describe('safeStringify with hostile keys', () => {
  it('keeps ordinary keys and never pollutes Object.prototype', () => {
    const payload = JSON.parse('{"ok":1,"__proto__":{"polluted":true},"constructor":{"x":1}}');
    const out = JSON.parse(safeStringify(payload));
    expect(out.ok).toBe(1);
    expect(({} as Record<string, unknown>)['polluted']).toBeUndefined();
  });
});
