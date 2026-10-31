import { assignOwn, isProtoKey } from '../own-property';
import { decycleValue, retrocycle, safeStringify } from '../safe-stringify';

const polluted = () => ({}) as Record<string, unknown>;

describe('isProtoKey', () => {
  it('matches only __proto__', () => {
    expect(isProtoKey('__proto__')).toBe(true);
    expect(isProtoKey('constructor')).toBe(false);
    expect(isProtoKey('prototype')).toBe(false);
    expect(isProtoKey('a')).toBe(false);
  });
});

describe('assignOwn', () => {
  it('assigns normal keys as enumerable, writable data properties', () => {
    const target: Record<string, unknown> = {};
    assignOwn(target, 'a', 1);
    target['a'] = 2;
    expect(target).toEqual({ a: 2 });
    expect(Object.keys(target)).toEqual(['a']);
  });

  it('stores __proto__ as an own property without changing the prototype', () => {
    const target: Record<string, unknown> = {};
    assignOwn(target, '__proto__', { polluted: true });
    expect(Object.getPrototypeOf(target)).toBe(Object.prototype);
    expect(Object.prototype.hasOwnProperty.call(target, '__proto__')).toBe(true);
    expect(Object.keys(target)).toEqual(['__proto__']);
    expect(polluted()['polluted']).toBeUndefined();
  });

  it('stores constructor and prototype as plain own properties', () => {
    const target: Record<string, unknown> = {};
    assignOwn(target, 'constructor', 'UserService');
    assignOwn(target, 'prototype', 'p');
    expect(target).toEqual({ constructor: 'UserService', prototype: 'p' });
    expect(Object.prototype.constructor).toBe(Object);
  });
});

describe('serializers keep hostile-looking keys', () => {
  const payload = () =>
    JSON.parse('{"constructor":"UserService","prototype":"p","__proto__":{"x":1},"ok":1}');

  it('safeStringify keeps constructor, prototype and an own __proto__ key', () => {
    const out = JSON.parse(safeStringify(payload()));
    expect(out.constructor).toBe('UserService');
    expect(out.prototype).toBe('p');
    expect(Object.prototype.hasOwnProperty.call(out, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(polluted()['x']).toBeUndefined();
  });

  it('decycleValue keeps constructor and an own __proto__ key', () => {
    const out = decycleValue(payload()) as Record<string, unknown>;
    expect(out['constructor']).toBe('UserService');
    expect(Object.prototype.hasOwnProperty.call(out, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
  });
});

describe('retrocycle', () => {
  it('does not resolve $ref through the prototype chain', () => {
    const parsed = JSON.parse('{"a":{"$ref":"$[\\"constructor\\"][\\"prototype\\"]"}}');
    const out = retrocycle(parsed) as Record<string, unknown>;
    expect(out['a']).not.toBe(Object.prototype);
    (out['a'] as Record<string, unknown>)['polluted'] = true;
    expect(polluted()['polluted']).toBeUndefined();
  });

  it('still resolves own-property and array pointers', () => {
    const shared = { n: 1 };
    const graph = { first: shared, second: shared, list: [shared] };
    const back = retrocycle(JSON.parse(JSON.stringify(decycleValue(graph)))) as typeof graph;
    expect(back.second).toBe(back.first);
    expect(back.list[0]).toBe(back.first);
  });
});
