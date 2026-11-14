import type { ITransport, TransportLogEntry } from '../../types/transport.types';
import { resetShutdownHandlers } from '../../utils/shutdown.utils';
import { LogixiaLogger } from '../logitron-logger';
import { LogixiaLoggerService } from '../logitron-nestjs.service';

const BASE = { appName: 'app', environment: 'test' };

function capture() {
  const entries: TransportLogEntry[] = [];
  const transport: ITransport = {
    name: 'cap',
    write: (e) => {
      entries.push(e);
    },
  };
  return { entries, transport };
}

afterEach(() => resetShutdownHandlers());

describe('logger redaction hardening', () => {
  it('does not reject on pathologically deep payloads', async () => {
    const { entries, transport } = capture();
    const logger = new LogixiaLogger({
      ...BASE,
      redact: { paths: ['**.password'] },
      transports: { custom: [transport] },
    } as never);
    const body = JSON.parse('['.repeat(30_000) + ']'.repeat(30_000)) as unknown;
    await expect(logger.info('req', { body })).resolves.toBeUndefined();
    expect(entries).toHaveLength(1);
  });

  it('accepts non-string messages when autoDetect is on', async () => {
    const { entries, transport } = capture();
    const logger = new LogixiaLogger({
      ...BASE,
      redact: { autoDetect: true },
      transports: { custom: [transport] },
    } as never);
    for (const m of [{ a: 1 }, ['a', 'b'], 42, null]) {
      await expect(logger.info(m as never)).resolves.toBeUndefined();
    }
    expect(entries).toHaveLength(4);
  });

  it('fails closed when redaction throws', async () => {
    const { entries, transport } = capture();
    const logger = new LogixiaLogger({
      ...BASE,
      redact: { paths: ['**.password'] },
      transports: { custom: [transport] },
    } as never);
    const hostile = new Proxy(
      {},
      {
        ownKeys() {
          throw new Error('trap');
        },
      }
    );
    await expect(logger.info('x', { password: 'LEAK', hostile })).resolves.toBeUndefined();
    const json = JSON.stringify(entries[0]);
    expect(json).not.toContain('LEAK');
    expect(json).toContain('[RedactionFailed]');
  });

  it('redacts Error props nested in the payload', async () => {
    const { entries, transport } = capture();
    const logger = new LogixiaLogger({
      ...BASE,
      redact: { paths: ['**.token'] },
      transports: { custom: [transport] },
    } as never);
    const err = Object.assign(new Error('boom'), { token: 'ERRTOK' });
    await logger.error('failed', { err });
    expect(JSON.stringify(entries[0])).not.toContain('ERRTOK');
  });
});

describe('an object logged as the message', () => {
  const redact = { paths: ['password', '**.cardNumber', 'user.ssn'], autoDetect: true };

  it('gets key and path rules, not only patterns', async () => {
    const { entries, transport } = capture();
    const logger = new LogixiaLogger({
      ...BASE,
      redact,
      transports: { custom: [transport] },
    } as never);
    await logger.info({
      email: 'a@b.c',
      password: 'hunter2',
      card: { cardNumber: '4111111111111111' },
      user: { ssn: '123-45-6789' },
    } as never);
    const message = String(entries[0]?.message);
    expect(message).toContain('a@b.c');
    expect(message).not.toContain('hunter2');
    expect(message).not.toContain('4111111111111111');
    expect(message).not.toContain('123-45-6789');
  });

  it('redacts each element of an array message as if logged alone', async () => {
    const { entries, transport } = capture();
    const logger = new LogixiaLogger({
      ...BASE,
      redact,
      transports: { custom: [transport] },
    } as never);
    await logger.info([
      { user: { ssn: '123-45-6789' } },
      'Bearer abc.def.ghi',
      [{ password: 'x' }],
    ] as never);
    const message = String(entries[0]?.message);
    expect(message.startsWith('[')).toBe(true);
    expect(message).not.toContain('123-45-6789');
    expect(message).not.toContain('abc.def.ghi');
    expect(message).not.toContain('"x"');
  });

  it('is redacted when NestJS code calls log(dto)', async () => {
    const { entries, transport } = capture();
    const service = new LogixiaLoggerService({
      ...BASE,
      redact,
      transports: { custom: [transport] },
    } as never);
    service.log({ email: 'a@b.c', password: 'hunter2' });
    service.warn({ password: 'hunter3' });
    await new Promise((resolve) => setImmediate(resolve));
    const messages = entries.map((e) => String(e.message)).join('\n');
    expect(messages).toContain('a@b.c');
    expect(messages).not.toContain('hunter2');
    expect(messages).not.toContain('hunter3');
  });
});

describe('default formatter control-character handling', () => {
  it('strips control characters from message, context and trace id', async () => {
    const writes: string[] = [];
    const spy = jest.spyOn(process.stdout, 'write').mockImplementation((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    });
    try {
      const logger = new LogixiaLogger(
        { ...BASE, format: { json: false, colorize: false, timestamp: false } } as never,
        'ctx\nFORGED'
      );
      await logger.info('ok\n[2026] ERROR forged \x1b[2J');
    } finally {
      spy.mockRestore();
    }
    const out = writes.join('');
    expect(out.endsWith('\n')).toBe(true);
    const body = out.slice(0, -1);
    expect(body.includes('\n') || body.includes('\r') || body.includes('\u001b')).toBe(false);
    expect(out).toContain('ctx\\nFORGED');
  });
});
