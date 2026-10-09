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
