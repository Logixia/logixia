/**
 * Tests for the @LogMethod decorator.
 *
 * Regression: the decorator unconditionally rewrote the method as `async` and
 * awaited the original, so a SYNCHRONOUS method silently started returning a
 * Promise — breaking callers that expected a direct value. The decorator must
 * now preserve the sync/async contract while still logging entry/exit/error.
 */

import { LogMethod } from '../nestjs-extras';

interface RecordedLog {
  level: string;
  message: string;
  data?: Record<string, unknown>;
}

function makeFakeLogger() {
  const logs: RecordedLog[] = [];
  const mk =
    (level: string) =>
    (message: string, data?: Record<string, unknown>): Promise<void> => {
      logs.push({ level, message, data });
      return Promise.resolve();
    };
  return {
    logs,
    logger: {
      debug: mk('debug'),
      info: mk('info'),
      warn: mk('warn'),
      verbose: mk('verbose'),
      trace: mk('trace'),
      error: (msg: unknown, data?: Record<string, unknown>) => {
        logs.push({ level: 'error', message: String(msg), data });
        return Promise.resolve();
      },
    },
  };
}

describe('@LogMethod — preserves sync/async contract', () => {
  it('a synchronous method still returns its value directly (not a Promise)', () => {
    const fake = makeFakeLogger();

    class Calc {
      logger = fake.logger;
      @LogMethod()
      add(a: number, b: number): number {
        return a + b;
      }
    }

    const result = new Calc().add(2, 3);
    expect(result).toBe(5);
    expect(result).not.toBeInstanceOf(Promise);
  });

  it('an async method returns a Promise that resolves to the value', async () => {
    const fake = makeFakeLogger();

    class Svc {
      logger = fake.logger;
      @LogMethod({ level: 'info' })
      async mul(a: number, b: number): Promise<number> {
        return a * b;
      }
    }

    const p = new Svc().mul(4, 5);
    expect(p).toBeInstanceOf(Promise);
    await expect(p).resolves.toBe(20);
  });

  it('logs entry and exit for a sync method', () => {
    const fake = makeFakeLogger();

    class Svc {
      logger = fake.logger;
      @LogMethod({ level: 'debug' })
      ping(): string {
        return 'pong';
      }
    }

    new Svc().ping();
    const messages = fake.logs.map((l) => l.message);
    expect(messages.some((m) => m.startsWith('→'))).toBe(true);
    expect(messages.some((m) => m.startsWith('←'))).toBe(true);
  });

  it('propagates and logs a synchronous throw', () => {
    const fake = makeFakeLogger();

    class Svc {
      logger = fake.logger;
      @LogMethod()
      boom(): void {
        throw new Error('sync boom');
      }
    }

    expect(() => new Svc().boom()).toThrow('sync boom');
    expect(fake.logs.some((l) => l.level === 'error')).toBe(true);
  });

  it('propagates and logs an async rejection', async () => {
    const fake = makeFakeLogger();

    class Svc {
      logger = fake.logger;
      @LogMethod()
      async fail(): Promise<void> {
        throw new Error('async boom');
      }
    }

    await expect(new Svc().fail()).rejects.toThrow('async boom');
    expect(fake.logs.some((l) => l.level === 'error')).toBe(true);
  });
});

describe('@LogMethod — arguments', () => {
  it('leaves positional arguments out by default', () => {
    const fake = makeFakeLogger();

    class LocalStrategy {
      logger = fake.logger;
      @LogMethod()
      validate(username: string, password: string): boolean {
        return username.length > 0 && password.length > 0;
      }
    }

    new LocalStrategy().validate('alice', 'correct-horse-battery-staple');
    expect(JSON.stringify(fake.logs)).not.toContain('correct-horse-battery-staple');
    expect(fake.logs.length).toBeGreaterThan(0);
  });

  it('logs arguments when logArgs is on', () => {
    const fake = makeFakeLogger();

    class Orders {
      logger = fake.logger;
      @LogMethod({ logArgs: true })
      find(orderId: string): string {
        return orderId;
      }
    }

    new Orders().find('o-42');
    expect(fake.logs.some((l) => JSON.stringify(l.data?.['args']) === '["o-42"]')).toBe(true);
  });
});
