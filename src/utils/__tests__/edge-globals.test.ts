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
  let savedSilent: string | undefined;
  let savedNodeEnv: string | undefined;
  const spies: jest.SpyInstance[] = [];

  beforeEach(() => {
    savedSilent = process.env.LOGIXIA_SILENT_INTERNAL;
    savedNodeEnv = process.env.NODE_ENV;
    delete process.env.LOGIXIA_SILENT_INTERNAL;
  });

  afterEach(() => {
    for (const spy of spies.splice(0)) spy.mockRestore();
    delete (globalThis as G)['LOGIXIA_SILENT_INTERNAL'];
    if (savedSilent === undefined) delete process.env.LOGIXIA_SILENT_INTERNAL;
    else process.env.LOGIXIA_SILENT_INTERNAL = savedSilent;
    if (savedNodeEnv === undefined) delete process.env.NODE_ENV;
    else process.env.NODE_ENV = savedNodeEnv;
  });

  const spyConsole = () => ({
    log: jest.spyOn(console, 'log').mockImplementation(() => {}),
    warn: jest.spyOn(console, 'warn').mockImplementation(() => {}),
    error: jest.spyOn(console, 'error').mockImplementation(() => {}),
  });

  it('internal-log uses the console method matching the level when process is missing', () => {
    const c = spyConsole();
    spies.push(c.log, c.warn, c.error);
    withoutProcess(() => {
      internalLog('hello');
      internalWarn('careful');
      internalError('broke', new Error('boom'));
    });
    expect(c.log).toHaveBeenCalledWith('[logixia] hello');
    expect(c.warn).toHaveBeenCalledWith('[logixia:warn] careful');
    expect(c.error).toHaveBeenCalledWith('[logixia:error] broke — boom');
  });

  it('internal-log falls back to console when process.stderr is missing', () => {
    const c = spyConsole();
    spies.push(c.log, c.warn, c.error);
    const originalStderr = Object.getOwnPropertyDescriptor(process, 'stderr')!;
    Object.defineProperty(process, 'stderr', { value: undefined, configurable: true });
    try {
      internalWarn('no stderr');
    } finally {
      Object.defineProperty(process, 'stderr', originalStderr);
    }
    expect(c.warn).toHaveBeenCalledWith('[logixia:warn] no stderr');
  });

  it('internal-log stays silent with LOGIXIA_SILENT_INTERNAL=1', () => {
    const c = spyConsole();
    spies.push(c.log, c.warn, c.error);
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    internalLog('x');
    internalError('x');
    expect(c.log).not.toHaveBeenCalled();
    expect(c.error).not.toHaveBeenCalled();
  });

  it('internal-log honors globalThis.LOGIXIA_SILENT_INTERNAL when process is missing', () => {
    const c = spyConsole();
    spies.push(c.log, c.warn, c.error);
    (globalThis as G)['LOGIXIA_SILENT_INTERNAL'] = '1';
    withoutProcess(() => internalError('x'));
    expect(c.error).not.toHaveBeenCalled();
  });

  it('defineLogSchema().validate works without process', () => {
    const schema = defineLogSchema<{ id: string }>({ id: { type: 'string', required: true } });
    const warnings = withoutProcess(() => schema.validate({}));
    expect(warnings).toEqual(['Required field "id" is missing']);
  });

  it('defineLogSchema().validate skips checks in production', () => {
    const schema = defineLogSchema<{ id: string }>({ id: { type: 'string', required: true } });
    process.env.NODE_ENV = 'production';
    expect(schema.validate({})).toEqual([]);
  });
});
