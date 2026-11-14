/**
 * Tests for `createTypedLogger` error-level schema validation.
 *
 * Regression: `error()` was the one level that skipped `schema.validate`,
 * so a missing required field or wrong type in an `error()` call produced no
 * warning. It now validates like every other level and still forwards the
 * original `Error` object untouched.
 */

import type { LoggerLike } from '../typed-logger';
import { createTypedLogger, defineLogSchema } from '../typed-logger';

interface OrderFields {
  orderId: string;
}

describe('createTypedLogger error validation', () => {
  const schema = defineLogSchema<OrderFields>({
    orderId: { type: 'string', required: true },
  });

  let writeSpy: jest.SpyInstance;
  let savedSilent: string | undefined;

  const makeBase = () =>
    ({
      error: jest.fn(),
      warn: jest.fn(),
      info: jest.fn(),
      debug: jest.fn(),
    }) as unknown as LoggerLike;

  beforeEach(() => {
    writeSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    savedSilent = process.env['LOGIXIA_SILENT_INTERNAL'];
    delete process.env['LOGIXIA_SILENT_INTERNAL'];
  });

  afterEach(() => {
    writeSpy.mockRestore();
    if (savedSilent === undefined) delete process.env['LOGIXIA_SILENT_INTERNAL'];
    else process.env['LOGIXIA_SILENT_INTERNAL'] = savedSilent;
  });

  it('validates error() data and emits a schema warning', async () => {
    const base = makeBase();
    const logger = createTypedLogger<OrderFields>(base, schema);

    await logger.error('payment failed', {});

    expect(base.error).toHaveBeenCalledWith('payment failed', {});
    const output = writeSpy.mock.calls.map((c) => String(c[0])).join('');
    expect(output).toContain('Required field "orderId" is missing');
    expect(output).toContain('level=error');
  });

  it('validates error(Error, data) and forwards the same Error instance', async () => {
    const err = new Error('boom');
    const base = makeBase();
    const logger = createTypedLogger<OrderFields>(base, schema);

    await logger.error(err, {});

    expect(base.error).toHaveBeenCalledWith(err, {});
    expect(base.error.mock.calls[0][0]).toBe(err);
    const output = writeSpy.mock.calls.map((c) => String(c[0])).join('');
    expect(output).toContain('message="boom"');
  });
});

describe('defineLogSchema().validate()', () => {
  let savedNodeEnv: string | undefined;

  beforeEach(() => {
    savedNodeEnv = process.env['NODE_ENV'];
  });

  afterEach(() => {
    if (savedNodeEnv === undefined) delete process.env['NODE_ENV'];
    else process.env['NODE_ENV'] = savedNodeEnv;
  });

  it('exposes the schema fields it was defined with', () => {
    const fields = { orderId: { type: 'string' as const, required: true } };
    expect(defineLogSchema<{ orderId: string }>(fields).fields).toBe(fields);
  });

  it('returns no warnings for a valid payload', () => {
    const schema = defineLogSchema<{ orderId: string; amount: number }>({
      orderId: { type: 'string', required: true },
      amount: { type: 'number' },
    });

    expect(schema.validate({ orderId: 'ord_1', amount: 9.99 })).toEqual([]);
  });

  it('warns about a missing required field', () => {
    const schema = defineLogSchema<{ orderId: string }>({
      orderId: { type: 'string', required: true },
    });

    expect(schema.validate({})).toEqual(['Required field "orderId" is missing']);
  });

  it('counts null as missing for a required field', () => {
    const schema = defineLogSchema<{ orderId: string }>({
      orderId: { type: 'string', required: true },
    });

    expect(schema.validate({ orderId: null as unknown as string })).toEqual([
      'Required field "orderId" is missing',
    ]);
  });

  it('does not warn about a missing optional field', () => {
    const schema = defineLogSchema<{ amount: number }>({ amount: { type: 'number' } });

    expect(schema.validate({})).toEqual([]);
  });

  it('warns when a value has the wrong type', () => {
    const schema = defineLogSchema<{ amount: number }>({ amount: { type: 'number' } });

    expect(schema.validate({ amount: '5' as unknown as number })).toEqual([
      'Field "amount" expected type "number" but got "string"',
    ]);
  });

  it('reports an array as "array", not "object"', () => {
    const schema = defineLogSchema<{ name: string }>({ name: { type: 'string' } });

    expect(schema.validate({ name: ['a'] as unknown as string })).toEqual([
      'Field "name" expected type "string" but got "array"',
    ]);
  });

  it('accepts an array for a field declared as "array"', () => {
    const schema = defineLogSchema<{ tags: string[] }>({ tags: { type: 'array' } });

    expect(schema.validate({ tags: ['a', 'b'] })).toEqual([]);
  });

  it('includes the message from a custom validate callback', () => {
    const schema = defineLogSchema<{ age: number }>({
      age: {
        type: 'number',
        validate: (v) => ((v as number) < 0 ? 'must not be negative' : undefined),
      },
    });

    expect(schema.validate({ age: -1 })).toEqual(['Field "age": must not be negative']);
    expect(schema.validate({ age: 3 })).toEqual([]);
  });

  it('does not call a custom validate callback for a missing value', () => {
    const validate = jest.fn();
    const schema = defineLogSchema<{ age: number }>({ age: { type: 'number', validate } });

    schema.validate({});

    expect(validate).not.toHaveBeenCalled();
  });

  it('returns no warnings when NODE_ENV is production', () => {
    const schema = defineLogSchema<{ orderId: string }>({
      orderId: { type: 'string', required: true },
    });
    process.env['NODE_ENV'] = 'production';

    expect(schema.validate({})).toEqual([]);
  });
});

describe('createTypedLogger', () => {
  interface OrderFields {
    orderId: string;
  }

  const schema = defineLogSchema<OrderFields>({
    orderId: { type: 'string', required: true },
  });

  let writeSpy: jest.SpyInstance;
  let savedSilent: string | undefined;

  const mockFn = () => jest.fn().mockResolvedValue(undefined);
  const makeBase = () => ({ error: mockFn(), warn: mockFn(), info: mockFn(), debug: mockFn() });
  const stderrOutput = () => writeSpy.mock.calls.map((c) => String(c[0])).join('');

  beforeEach(() => {
    writeSpy = jest.spyOn(process.stderr, 'write').mockImplementation(() => true);
    savedSilent = process.env['LOGIXIA_SILENT_INTERNAL'];
    delete process.env['LOGIXIA_SILENT_INTERNAL'];
  });

  afterEach(() => {
    writeSpy.mockRestore();
    if (savedSilent === undefined) delete process.env['LOGIXIA_SILENT_INTERNAL'];
    else process.env['LOGIXIA_SILENT_INTERNAL'] = savedSilent;
  });

  it.each(['info', 'warn', 'debug'] as const)(
    '%s() forwards the same message and data to the base logger',
    async (level) => {
      const base = makeBase();
      const logger = createTypedLogger<OrderFields>(base, schema);

      await logger[level]('order created', { orderId: 'ord_1' });

      expect(base[level]).toHaveBeenCalledTimes(1);
      expect(base[level]).toHaveBeenCalledWith('order created', { orderId: 'ord_1' });
    }
  );

  it('forwards undefined data when none is passed', async () => {
    const base = makeBase();
    const logger = createTypedLogger<OrderFields>(base, schema);

    await logger.info('no data');

    expect(base.info).toHaveBeenCalledWith('no data', undefined);
  });

  it.each(['verbose', 'trace'] as const)(
    '%s() falls back to debug when the base logger lacks it',
    async (level) => {
      const base = makeBase();
      const logger = createTypedLogger<OrderFields>(base, schema);

      await logger[level]('fine detail', { orderId: 'ord_1' });

      expect(base.debug).toHaveBeenCalledWith('fine detail', { orderId: 'ord_1' });
    }
  );

  it.each(['verbose', 'trace'] as const)(
    '%s() uses the base logger method when it exists',
    async (level) => {
      const base = { ...makeBase(), verbose: mockFn(), trace: mockFn() };
      const logger = createTypedLogger<OrderFields>(base, schema);

      await logger[level]('fine detail', { orderId: 'ord_1' });

      expect(base[level]).toHaveBeenCalledWith('fine detail', { orderId: 'ord_1' });
      expect(base.debug).not.toHaveBeenCalled();
    }
  );

  it.each(['warn', 'info', 'debug', 'verbose', 'trace'] as const)(
    '%s() writes schema warnings to stderr and still forwards the call',
    async (level) => {
      const base = makeBase();
      const logger = createTypedLogger<OrderFields>(base, schema);

      await logger[level]('missing id', {});

      const output = stderrOutput();
      expect(output).toContain('[logixia/schema] Required field "orderId" is missing');
      expect(output).toContain(`level=${level}`);
      expect(output).toContain('message="missing id"');
      expect(base[level === 'verbose' || level === 'trace' ? 'debug' : level]).toHaveBeenCalledWith(
        'missing id',
        {}
      );
    }
  );

  it('writes nothing to stderr when the data matches the schema', async () => {
    const logger = createTypedLogger<OrderFields>(makeBase(), schema);

    await logger.info('ok', { orderId: 'ord_1' });

    expect(writeSpy).not.toHaveBeenCalled();
  });

  it('does not validate when no schema is given', async () => {
    const base = makeBase();
    const logger = createTypedLogger<OrderFields>(base);

    await logger.warn('no schema', {});

    expect(writeSpy).not.toHaveBeenCalled();
    expect(base.warn).toHaveBeenCalledWith('no schema', {});
  });

  it('does not validate when no data is passed', async () => {
    const logger = createTypedLogger<OrderFields>(makeBase(), schema);

    await logger.info('no data');

    expect(writeSpy).not.toHaveBeenCalled();
  });

  it('exposes the original logger as raw', () => {
    const base = makeBase();

    expect(createTypedLogger<OrderFields>(base, schema).raw).toBe(base);
  });
});
