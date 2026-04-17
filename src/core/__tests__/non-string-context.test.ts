/**
 * Regression tests for non-string context handling.
 *
 * Background: downstream consumers (NestJS framework internals, user code,
 * library glue) sometimes pass non-string values into the context slot —
 * either by calling `setContext({...})` directly or by handing an object
 * to `LogixiaLoggerService.log(message, optionalParam)`.
 *
 * Before the fix:
 *   - the object was stored verbatim on `this.context`, then later printed
 *     as `[[object Object]]`
 *   - the text formatter / console transport called `.replace()` on
 *     `entry.context` and crashed with "value.replace is not a function"
 *
 * These tests pin both behaviors so they cannot regress.
 */

import { LogixiaContext } from '../../context/async-context';
import { resetShutdownHandlers } from '../../utils/shutdown.utils';
import { LogixiaLogger } from '../logitron-logger';
import { LogixiaLoggerService } from '../logitron-nestjs.service';

const BASE_CONFIG = {
  appName: 'TestApp',
  environment: 'development' as const,
  format: { timestamp: false, colorize: false, json: false },
  traceId: false,
  silent: false,
};

function spyOutput() {
  const lines: string[] = [];
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  (process.stdout as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };
  (process.stderr as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };
  return {
    joined: () => lines.join(''),
    restore: () => {
      (process.stdout as NodeJS.WriteStream).write = origOut as typeof process.stdout.write;
      (process.stderr as NodeJS.WriteStream).write = origErr as typeof process.stderr.write;
    },
  };
}

beforeEach(() => {
  resetShutdownHandlers();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');
  delete process.env['LOGIXIA_LEVEL'];
  process.env['NODE_ENV'] = 'test';
});

afterEach(() => {
  resetShutdownHandlers();
  process.removeAllListeners('SIGTERM');
  process.removeAllListeners('SIGINT');
});

describe('LogixiaLogger.setContext — defensive coercion', () => {
  it('coerces a non-string object to a string', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });

    logger.setContext({ anObject: true } as any);
    expect(typeof logger.getContext()).toBe('string');
    // Should never be the literal "[object Object]" — JSON-stringified instead
    expect(logger.getContext()).not.toBe('[object Object]');
    expect(logger.getContext()).toContain('anObject');
  });

  it('does not throw when an object context flows through the text formatter', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });

    logger.setContext({ notAString: 'oops' } as any);
    await expect(logger.info('after weird setContext')).resolves.toBeUndefined();
    out.restore();
    expect(out.joined()).toContain('after weird setContext');
    // No "[object Object]" leak — the object was JSON-stringified.
    expect(out.joined()).not.toContain('[object Object]');
  });

  it('passes plain string contexts through unchanged', () => {
    const logger = new LogixiaLogger({ ...BASE_CONFIG });
    logger.setContext('MyService');
    expect(logger.getContext()).toBe('MyService');
  });
});

describe('LogixiaLoggerService — NestJS adapter', () => {
  it('does not throw when log() receives a non-string second arg', () => {
    const service = new LogixiaLoggerService({
      appName: 'NestApp',
      format: { json: false, colorize: false, timestamp: false },
    });
    const fakeExecContext = { switchToHttp: () => ({}) };
    expect(() =>
      service.log('NestJS module loaded', fakeExecContext as unknown as string)
    ).not.toThrow();
    // Object arg must be ignored — not stored as context.
    expect(service.getContext()).not.toEqual(fakeExecContext);
  });

  it('setContext({}) coerces to string and downstream logging does not throw', async () => {
    const service = new LogixiaLoggerService({
      appName: 'NestApp',
      format: { json: false, colorize: false, timestamp: false },
    });

    service.setContext({ anObject: true } as any);
    expect(typeof service.getContext()).toBe('string');
    await expect(service.info('hi after weird setContext')).resolves.toBeUndefined();
  });

  it('does not throw when error() is called with an Error and metadata containing a cause', async () => {
    const service = new LogixiaLoggerService({
      appName: 'NestApp',
      format: { json: false, colorize: false, timestamp: false },
    });
    service.setContext('TestCtx');
    await expect(
      service.error('failed', { cause: new Error('underlying') })
    ).resolves.toBeUndefined();
  });

  it('error() with NestJS-style (message, stack, context) signature works', () => {
    const service = new LogixiaLoggerService({
      appName: 'NestApp',
      format: { json: false, colorize: false, timestamp: false },
    });
    expect(() => service.error('Boom', 'stack-trace-here', 'AuthService')).not.toThrow();
    expect(service.getContext()).toBe('AuthService');
  });

  it('warn/debug/verbose ignore non-string second args silently', () => {
    const service = new LogixiaLoggerService({
      appName: 'NestApp',
      format: { json: false, colorize: false, timestamp: false },
    });
    service.setContext('Initial');
    // Pass a plain object that is treated as data — must not crash, must not
    // overwrite context with the object.
    service.warn('w', { foo: 'bar' });
    service.debug('d', { foo: 'bar' });
    service.verbose('v', { foo: 'bar' });
    expect(service.getContext()).toBe('Initial');
  });
});

describe('AsyncLocalStorage interplay', () => {
  it('does not break inside a LogixiaContext.run with object context', async () => {
    const out = spyOutput();
    const logger = new LogixiaLogger({ ...BASE_CONFIG, levelOptions: { level: 'info' } });

    logger.setContext({ unexpected: 'shape' } as any);
    await LogixiaContext.run({ requestId: 'r1' }, async () => {
      await expect(logger.info('inside ALS')).resolves.toBeUndefined();
    });
    out.restore();
    expect(out.joined()).toContain('inside ALS');
  });
});
