import { createLogger } from '../index';

const lines: string[] = [];
const capture = (line: unknown) => {
  lines.push(String(line));
};
const captureWrite = (chunk: unknown) => {
  capture(chunk);
  return true;
};
const spies = [
  jest.spyOn(console, 'log').mockImplementation(capture),
  jest.spyOn(console, 'info').mockImplementation(capture),
  jest.spyOn(console, 'warn').mockImplementation(capture),
  jest.spyOn(console, 'error').mockImplementation(capture),
  jest.spyOn(process.stdout, 'write').mockImplementation(captureWrite),
  jest.spyOn(process.stderr, 'write').mockImplementation(captureWrite),
];

afterAll(() => {
  for (const spy of spies) spy.mockRestore();
});
beforeEach(() => {
  lines.length = 0;
});

const loggerWith = (redact?: Parameters<typeof createLogger>[0]['redact']) =>
  createLogger({
    appName: 'test',
    environment: 'production',
    traceId: false,
    format: { json: true, timestamp: true, colorize: false },
    ...(redact ? { redact } : {}),
  });

const lastEntry = (): { payload: Record<string, any> } => JSON.parse(lines.at(-1) ?? '{}');

describe('errors in a log payload', () => {
  it('writes an Error held in a field', async () => {
    await loggerWith().error('failed', { error: new Error('kaboom'), requestId: 'r1' });
    const { payload } = lastEntry();
    expect(payload.error.message).toBe('kaboom');
    expect(payload.error.stack).toContain('kaboom');
    expect(payload.requestId).toBe('r1');
  });

  it('writes an Error passed as the second argument', async () => {
    const data = new Error('second') as unknown as Record<string, unknown>;
    await loggerWith().error('failed', data);
    expect(lastEntry().payload.error.message).toBe('second');
  });

  it('works at every level, not just error', async () => {
    await loggerWith().warn('slow', { cause: new Error('timeout') });
    expect(lastEntry().payload.cause.message).toBe('timeout');
  });

  it('redacts a secret inside an error message', async () => {
    const logger = loggerWith({ patterns: [/secret-[a-z0-9]+/g] });
    await logger.error('failed', { error: new Error('token secret-abc123 rejected') });
    const line = lines.at(-1) ?? '';
    expect(line).not.toContain('secret-abc123');
    expect(line).toContain('rejected');
  });

  it('redacts by path inside a serialized error', async () => {
    const logger = loggerWith({ paths: ['error.message', 'error.stack'] });
    await logger.error('failed', { error: new Error('hide me') });
    expect(lines.at(-1)).not.toContain('hide me');
  });

  it('still redacts by path when a payload looks like an error', async () => {
    const logger = loggerWith({ paths: ['email', 'ssn'] });
    await logger.info('contact', { name: 'Bob', message: 'hi', email: 'b@x.com', ssn: '123' });
    const line = lines.at(-1) ?? '';
    expect(line).not.toContain('b@x.com');
    expect(line).not.toContain('123');
    expect(lastEntry().payload.name).toBe('Bob');
  });

  it('keeps an Error passed as the second argument inside a context', async () => {
    const child = loggerWith().child('svc', { tenant: 't1' });
    const data = new Error('in child') as unknown as Record<string, unknown>;
    await child.error('failed', data);
    expect(lastEntry().payload).toMatchObject({ tenant: 't1', error: { message: 'in child' } });
  });

  it('never rejects on a hostile getter, with or without redaction', async () => {
    const hostile = Object.defineProperty({}, 'boom', {
      enumerable: true,
      get() {
        throw new Error('hostile');
      },
    });
    await expect(loggerWith().info('x', { hostile })).resolves.toBeUndefined();
    await expect(
      loggerWith({ paths: ['password'] }).info('x', { hostile })
    ).resolves.toBeUndefined();
  });

  it('leaves a payload with no error as it was', async () => {
    await loggerWith().info('fine', { count: 1, nested: { ok: true } });
    expect(lastEntry().payload).toEqual({ count: 1, nested: { ok: true } });
  });
});
