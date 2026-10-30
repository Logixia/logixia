import { internalError, internalLog, internalWarn } from '../internal-log';
import { defineLogSchema } from '../typed-logger';

type G = Record<string, unknown>;

function withoutProcess<T>(fn: () => T): T {
  const g = globalThis as unknown as G;
  const original = g['process'];
  g['process'] = undefined;
  try {
    return fn();
  } finally {
    g['process'] = original;
  }
}

describe('Node-global guards (edge runtimes)', () => {
  it('internal-log falls back to console.error when process is missing', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    withoutProcess(() => {
      internalLog('hello');
      internalWarn('careful');
      internalError('broke', new Error('boom'));
    });
    expect(spy.mock.calls.map((c) => c[0])).toEqual([
      '[logixia] hello',
      '[logixia:warn] careful',
      '[logixia:error] broke — boom',
    ]);
    spy.mockRestore();
  });

  it('internal-log falls back to console.error when process.stderr is missing', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const originalStderr = Object.getOwnPropertyDescriptor(process, 'stderr')!;
    Object.defineProperty(process, 'stderr', { value: undefined, configurable: true });
    const prev = process.env.LOGIXIA_SILENT_INTERNAL;
    delete process.env.LOGIXIA_SILENT_INTERNAL;
    try {
      internalWarn('no stderr');
    } finally {
      Object.defineProperty(process, 'stderr', originalStderr);
      if (prev !== undefined) process.env.LOGIXIA_SILENT_INTERNAL = prev;
    }
    expect(spy).toHaveBeenCalledWith('[logixia:warn] no stderr');
    spy.mockRestore();
  });

  it('internal-log stays silent with LOGIXIA_SILENT_INTERNAL=1', () => {
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    const prev = process.env.LOGIXIA_SILENT_INTERNAL;
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    try {
      internalLog('x');
    } finally {
      if (prev === undefined) delete process.env.LOGIXIA_SILENT_INTERNAL;
      else process.env.LOGIXIA_SILENT_INTERNAL = prev;
    }
    expect(spy).not.toHaveBeenCalled();
    spy.mockRestore();
  });

  it('defineLogSchema().validate works without process', () => {
    const schema = defineLogSchema<{ id: string }>({ id: { type: 'string', required: true } });
    const warnings = withoutProcess(() => schema.validate({}));
    expect(warnings).toEqual(['Required field "id" is missing']);
  });

  it('defineLogSchema().validate skips checks in production', () => {
    const schema = defineLogSchema<{ id: string }>({ id: { type: 'string', required: true } });
    const prev = process.env.NODE_ENV;
    process.env.NODE_ENV = 'production';
    try {
      expect(schema.validate({})).toEqual([]);
    } finally {
      process.env.NODE_ENV = prev;
    }
  });
});
