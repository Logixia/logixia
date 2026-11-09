import { serializeNestedErrors } from '../error.utils';

describe('serializeNestedErrors', () => {
  it('keeps name, message and stack for an Error in a field', () => {
    const result = serializeNestedErrors({ error: new TypeError('bad input') });
    expect(result.error).toMatchObject({ name: 'TypeError', message: 'bad input' });
    expect(typeof (result.error as { stack: unknown }).stack).toBe('string');
  });

  it('finds errors in nested objects and arrays', () => {
    const result = serializeNestedErrors({
      job: { failure: new Error('nested') },
      attempts: [new Error('first'), 'text'],
    });
    expect(result).toMatchObject({
      job: { failure: { message: 'nested' } },
      attempts: [{ message: 'first' }, 'text'],
    });
  });

  it('keeps the cause chain and extra fields', () => {
    const error = Object.assign(new Error('outer', { cause: new Error('inner') }), {
      code: 'E_DB',
    });
    expect(serializeNestedErrors({ error }).error).toMatchObject({
      message: 'outer',
      code: 'E_DB',
      cause: { message: 'inner' },
    });
  });

  it('returns the same object when there is no error', () => {
    const data = { a: 1, b: { c: [1, 2] } };
    const result = serializeNestedErrors(data);
    expect(result).toBe(data);
    expect(result.b).toBe(data.b);
  });

  it("never mutates the caller's objects", () => {
    const inner = { failure: new Error('x') };
    const data = { inner };
    const result = serializeNestedErrors(data);
    expect(data.inner).toBe(inner);
    expect(inner.failure).toBeInstanceOf(Error);
    expect(result.inner).not.toBe(inner);
  });

  it('does not unroll a cycle into repeated errors', () => {
    const data: Record<string, unknown> = { error: new Error('x') };
    data.self = data;
    const result = serializeNestedErrors(data);
    expect(result.error).toMatchObject({ message: 'x' });
    expect(result.self).toBe(data);
  });

  it('treats an object with name and message as data', () => {
    const contact = { name: 'Bob', message: 'hi', email: 'b@x.com' };
    const data = { contact };
    expect(serializeNestedErrors(data)).toBe(data);
    class Ticket {
      name = 'n';
      message = 'm';
      secretNote = 'private';
    }
    const values = { ticket: new Ticket() };
    expect(serializeNestedErrors(values)).toBe(values);
  });

  it('leaves an Error with its own toJSON alone', () => {
    const error = Object.assign(new Error('x'), { toJSON: () => ({ safe: true }) });
    expect(serializeNestedErrors({ error }).error).toBe(error);
  });

  it('skips a throwing getter and still serializes the error beside it', () => {
    const meta = Object.defineProperty({}, 'boom', {
      enumerable: true,
      get() {
        throw new Error('hostile');
      },
    });
    expect(serializeNestedErrors({ error: new Error('real'), meta }).error).toMatchObject({
      message: 'real',
    });
  });

  it('stops walking after its node budget on a huge payload', () => {
    const late = { failure: new Error('past the budget') };
    const rows: unknown[] = Array.from({ length: 5000 }, () => ({ a: {} }));
    rows.push(late);
    const data = { rows };
    expect(serializeNestedErrors(data)).toBe(data);
    expect(late.failure).toBeInstanceOf(Error);
  });

  it('leaves dates, maps and class instances alone', () => {
    class Money {
      constructor(readonly paise: number) {}
    }
    const values = { at: new Date(0), map: new Map([[1, 2]]), money: new Money(5) };
    expect(serializeNestedErrors(values)).toBe(values);
  });

  it('stops looking past its depth limit', () => {
    const deep = { a: { b: { c: { d: { error: new Error('too deep') } } } } };
    expect(serializeNestedErrors(deep)).toBe(deep);
  });

  it('is not fooled by a __proto__ key', () => {
    const data = JSON.parse('{"__proto__": {"polluted": true}, "error": null}') as Record<
      string,
      unknown
    >;
    data.error = new Error('x');
    serializeNestedErrors(data);
    expect(({} as { polluted?: boolean }).polluted).toBeUndefined();
  });
});
