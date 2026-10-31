import { LogixiaContext } from '../../context/async-context';
import { JsonFormatter } from '../../formatters/json.formatter';
import { redactConfig } from '../../transports/secret-config';
import { serializeError } from '../error.utils';
import { redactObject } from '../redact.utils';

const hasOwn = (o: object, k: string) => Object.prototype.hasOwnProperty.call(o, k);

describe('redactConfig with hostile keys', () => {
  it('keeps a JSON-parsed __proto__ key as an own key and leaves the prototype alone', () => {
    const out = redactConfig(
      JSON.parse('{"__proto__":{"apiKey":"s3cret","safe":1},"host":"h"}')
    ) as Record<string, unknown>;
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(hasOwn(out, '__proto__')).toBe(true);
    expect(JSON.stringify(out)).not.toContain('s3cret');
    expect(out.host).toBe('h');
  });

  it('keeps constructor fields', () => {
    expect((redactConfig({ constructor: 'x' }) as Record<string, unknown>).constructor).toBe('x');
  });
});

describe('redactObject with hostile keys', () => {
  it('keeps constructor/prototype/__proto__ as own keys while still redacting', () => {
    const input = JSON.parse(
      '{"constructor":"UserService","prototype":"p","__proto__":{"x":1},"password":"pw"}'
    );
    const out = redactObject(input, { paths: ['password'] });
    expect(out['constructor']).toBe('UserService');
    expect(out['prototype']).toBe('p');
    expect(out['password']).not.toBe('pw');
    expect(hasOwn(out, '__proto__')).toBe(true);
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
  });
});

describe('serializeError with hostile keys', () => {
  it('keeps a constructor field on nested plain objects', () => {
    const err = Object.assign(new Error('boom'), { meta: { constructor: 'UserService' } });
    const out = serializeError(err) as Record<string, unknown>;
    expect((out['meta'] as Record<string, unknown>)['constructor']).toBe('UserService');
  });
});

describe('LogixiaContext.set with hostile keys', () => {
  it('keeps constructor and stores __proto__ as an own key', () => {
    LogixiaContext.run({ a: 1 }, () => {
      LogixiaContext.set(JSON.parse('{"constructor":"svc","__proto__":{"polluted":"yes"}}'));
      const ctx = LogixiaContext.get() as Record<string, unknown>;
      expect(ctx['constructor']).toBe('svc');
      expect(ctx['polluted']).toBeUndefined();
      expect(Object.getPrototypeOf(ctx)).toBe(Object.prototype);
    });
  });
});

describe('JsonFormatter with hostile keys', () => {
  it('keeps a constructor payload field', () => {
    const out = JSON.parse(
      new JsonFormatter().format({
        timestamp: new Date().toISOString(),
        level: 'info',
        appName: 'a',
        environment: 'test',
        message: 'm',
        payload: JSON.parse('{"constructor":"UserService","__proto__":{"x":1}}'),
      } as never)
    );
    expect(JSON.stringify(out)).toContain('UserService');
    expect(({} as Record<string, unknown>)['x']).toBeUndefined();
  });
});
