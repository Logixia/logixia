/**
 * Tests covering the three custom-level improvements:
 *
 *  1. LogixiaLoggerService — dynamic proxy methods for custom levels
 *     (so `service.payment('msg')` works without casting)
 *
 *  2. LogixiaLogger — auto-palette colors for custom levels that have no
 *     explicit color configured (so KAFKA / MYSQL look colored, not white)
 *
 *  3. LogixiaLogger — logLevel() / shouldLog with custom levels
 */

import { createLogger, LogixiaLogger } from '../logitron-logger';
import { LogixiaLoggerService } from '../logitron-nestjs.service';

// ── Helpers ───────────────────────────────────────────────────────────────────

const BASE_CONFIG = {
  appName: 'TestApp',
  environment: 'development' as const,
  format: { timestamp: false, colorize: false, json: false },
  traceId: false,
  silent: false,
};

const BASE_CONFIG_COLOR = {
  ...BASE_CONFIG,
  format: { timestamp: false, colorize: true, json: false },
};

/** Intercept stdout/stderr writes and return captured lines + restore fn. */
function captureOutput() {
  const lines: string[] = [];
  const origStdout = process.stdout.write.bind(process.stdout);
  const origStderr = process.stderr.write.bind(process.stderr);

  (process.stdout as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };
  (process.stderr as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };

  return {
    get lines() {
      return lines;
    },
    restore() {
      (process.stdout as NodeJS.WriteStream).write = origStdout as typeof process.stdout.write;
      (process.stderr as NodeJS.WriteStream).write = origStderr as typeof process.stderr.write;
    },
  };
}

// ── 1. LogixiaLoggerService — custom level proxy methods ──────────────────────

describe('LogixiaLoggerService — custom level proxy methods', () => {
  it('attaches a method for each custom level on the service instance', () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        levels: { error: 0, warn: 1, info: 2, payment: 3, audit: 4 },
      },
    });

    expect(typeof (svc as any).payment).toBe('function');
    expect(typeof (svc as any).audit).toBe('function');
  });

  it('proxy method returns a Promise', async () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
      },
    });

    const result = (svc as any).kafka('test message');
    expect(result).toBeInstanceOf(Promise);
    await result; // must not throw
  });

  it('proxy method routes through logLevel with the correct level name', async () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        levels: { error: 0, warn: 1, info: 2, payment: 3 },
        level: 'payment',
      },
    });

    const captured = captureOutput();
    try {
      await (svc as any).payment('payment processed');
      expect(captured.lines.some((l) => l.includes('payment processed'))).toBe(true);
    } finally {
      captured.restore();
    }
  });

  it('proxy method passes structured data to the underlying logger', async () => {
    const svc = new LogixiaLoggerService({
      format: { timestamp: false, colorize: false, json: false },
      traceId: false,
      levelOptions: {
        levels: { error: 0, warn: 1, info: 2, audit: 3 },
        level: 'audit',
      },
    });

    const captured = captureOutput();
    try {
      await (svc as any).audit('user login', { userId: 'u_001', action: 'login' });
      const joined = captured.lines.join('');
      expect(joined).toContain('user login');
      expect(joined).toContain('u_001');
    } finally {
      captured.restore();
    }
  });

  it('does NOT overwrite built-in methods (log, warn, error, debug, verbose)', () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        levels: { error: 0, warn: 1, log: 2, debug: 3, verbose: 4 },
      },
    });

    // All of these must still be the built-in implementations (not the proxy lambda)
    expect(svc.log).toBeDefined();
    expect(svc.warn).toBeDefined();
    expect(svc.error).toBeDefined();
    expect(svc.debug).toBeDefined();
    expect(svc.verbose).toBeDefined();

    // The built-in methods are defined on the prototype; the proxies are own properties.
    // Built-in methods should NOT have been replaced by a proxy arrow function
    // (prototype methods are not own enumerable properties).
    expect(Object.prototype.hasOwnProperty.call(svc, 'log')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(svc, 'warn')).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(svc, 'error')).toBe(false);
  });

  it('multiple custom levels all get proxy methods', () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        levels: {
          error: 0,
          warn: 1,
          info: 2,
          kafka: 3,
          mysql: 4,
          payment: 5,
          audit: 6,
        },
      },
    });

    for (const level of ['kafka', 'mysql', 'payment', 'audit']) {
      expect(typeof (svc as any)[level]).toBe('function');
    }
  });

  it('static LogixiaLoggerService.create() also produces custom-level proxy methods', () => {
    const svc = LogixiaLoggerService.create({
      levelOptions: {
        levels: { error: 0, warn: 1, info: 2, sms: 3 },
      },
    });

    expect(typeof (svc as any).sms).toBe('function');
  });

  it('custom level method can be called with no data argument', async () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        levels: { error: 0, warn: 1, info: 2, notify: 3 },
        level: 'notify',
      },
    });

    // Should resolve without throwing
    await expect((svc as any).notify('just a message')).resolves.toBeUndefined();
  });

  it('logLevel() works as a typed escape hatch for any level string', async () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        levels: { error: 0, warn: 1, info: 2, payment: 3 },
        level: 'payment',
      },
    });

    const captured = captureOutput();
    try {
      await svc.logLevel('payment', 'via logLevel escape hatch', { ref: 'txn_99' });
      const joined = captured.lines.join('');
      expect(joined).toContain('via logLevel escape hatch');
    } finally {
      captured.restore();
    }
  });
});

// ── 2. LogixiaLogger — auto-palette colors for custom levels ──────────────────

// ESC character — defined once to avoid no-control-regex lint errors on inline literals
const ESC = String.fromCharCode(27);
const ANSI_RE = new RegExp(`${ESC}\\[\\d+m`);
const ANSI_CAPTURE_RE = new RegExp(`${ESC}\\[(\\d+)m`);

describe('LogixiaLogger — auto-palette colors for custom levels', () => {
  /** Extract the ANSI color codes present in a string */
  function hasAnsiColor(str: string): boolean {
    return ANSI_RE.test(str);
  }

  /** Extract the raw ANSI code prefix from a formatted level string like "[ESC[35mKAFKA...]" */
  function extractAnsiCode(str: string): string | null {
    const match = str.match(ANSI_CAPTURE_RE);
    return match ? (match[1] ?? null) : null;
  }

  it('custom level without explicit color produces ANSI-colored output', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
        // No colors defined for kafka
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('kafka', 'kafka message');
      const output = captured.lines.join('');
      expect(hasAnsiColor(output)).toBe(true);
    } finally {
      captured.restore();
    }
  });

  it('first custom level gets magenta (ANSI code 35)', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
        colors: { error: 'red', warn: 'yellow', info: 'blue' },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('kafka', 'first custom level');
      const output = captured.lines.join('');
      // Magenta = ESC[35m
      expect(output).toContain(`${ESC}[35m`);
    } finally {
      captured.restore();
    }
  });

  it('second custom level gets cyan (ANSI code 36)', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'mysql',
        levels: { error: 0, warn: 1, info: 2, kafka: 3, mysql: 4 },
        colors: { error: 'red', warn: 'yellow', info: 'blue' },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('mysql', 'second custom level');
      const output = captured.lines.join('');
      // Cyan = ESC[36m
      expect(output).toContain(`${ESC}[36m`);
    } finally {
      captured.restore();
    }
  });

  it('palette cycles: magenta → cyan → yellow → green → blue', () => {
    // Access the internal _formattedLevels map to verify palette assignment
    const levels = {
      error: 0,
      warn: 1,
      info: 2,
      lv1: 3,
      lv2: 4,
      lv3: 5,
      lv4: 6,
      lv5: 7,
    };
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'lv1',
        levels,
        colors: { error: 'red', warn: 'yellow', info: 'blue' },
      },
    }) as any;

    const palette = [
      `${ESC}[35m`, // magenta
      `${ESC}[36m`, // cyan
      `${ESC}[33m`, // yellow
      `${ESC}[32m`, // green
      `${ESC}[34m`, // blue
    ];

    const customLevels = ['lv1', 'lv2', 'lv3', 'lv4', 'lv5'];
    for (let i = 0; i < customLevels.length; i++) {
      const formatted: string = logger._formattedLevels.get(customLevels[i]) ?? '';
      expect(formatted).toContain(palette[i % palette.length]);
    }
  });

  it('explicit color in config overrides the auto-palette', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
        colors: { kafka: 'green' }, // explicit: green, not magenta
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('kafka', 'explicit color test');
      const output = captured.lines.join('');
      // Green = ESC[32m
      expect(output).toContain(`${ESC}[32m`);
      // Should NOT have magenta
      expect(output).not.toContain(`${ESC}[35m`);
    } finally {
      captured.restore();
    }
  });

  it('colorize: false produces no ANSI codes even for custom levels', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG, // colorize: false
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('kafka', 'no-color test');
      const output = captured.lines.join('');
      expect(hasAnsiColor(output)).toBe(false);
      expect(output).toContain('[KAFKA]');
    } finally {
      captured.restore();
    }
  });

  it('different custom levels produce visually distinct colors', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3, mysql: 4 },
        colors: { error: 'red', warn: 'yellow', info: 'blue' },
      },
    }) as any;

    const kafkaFormatted: string = logger._formattedLevels.get('kafka') ?? '';
    const mysqlFormatted: string = logger._formattedLevels.get('mysql') ?? '';

    const kafkaCode = extractAnsiCode(kafkaFormatted);
    const mysqlCode = extractAnsiCode(mysqlFormatted);

    // Both must have colors, and they must be different
    expect(kafkaCode).not.toBeNull();
    expect(mysqlCode).not.toBeNull();
    expect(kafkaCode).not.toBe(mysqlCode);
  });

  it('setLevel rebuild keeps custom level colors intact', () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
        colors: { error: 'red', warn: 'yellow', info: 'blue' },
      },
    }) as any;

    const before: string = logger._formattedLevels.get('kafka') ?? '';
    logger.setLevel('info');
    const after: string = logger._formattedLevels.get('kafka') ?? '';

    // Color should be stable across setLevel
    expect(extractAnsiCode(before)).toBe(extractAnsiCode(after));
  });
});

// ── 3. LogixiaLogger — custom level filtering / shouldLog ─────────────────────

describe('LogixiaLogger — custom level filtering', () => {
  it('custom level at the active threshold is logged', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'payment',
        levels: { error: 0, warn: 1, info: 2, payment: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('payment', 'charged $100');
      expect(captured.lines.join('')).toContain('charged $100');
    } finally {
      captured.restore();
    }
  });

  it('custom level below the active threshold is suppressed', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'warn', // active level = 1 (only error:0 and warn:1 pass)
        levels: { error: 0, warn: 1, info: 2, payment: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('payment', 'should be suppressed');
      expect(captured.lines.join('')).not.toContain('should be suppressed');
    } finally {
      captured.restore();
    }
  });

  it('custom level above the active threshold is logged when threshold is raised', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'audit',
        levels: { error: 0, warn: 1, info: 2, payment: 3, audit: 4 },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('payment', 'payment passes');
      await logger.logLevel('audit', 'audit passes');
      const out = captured.lines.join('');
      expect(out).toContain('payment passes');
      expect(out).toContain('audit passes');
    } finally {
      captured.restore();
    }
  });

  it('createLogger attaches all custom level methods', () => {
    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3, mysql: 4, payment: 5 },
      },
    });

    for (const lvl of ['kafka', 'mysql', 'payment']) {
      expect(typeof (logger as any)[lvl]).toBe('function');
    }
  });

  it('createLogger custom method actually logs at the correct level', async () => {
    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await (logger as any).kafka('kafka event fired');
      expect(captured.lines.join('')).toContain('kafka event fired');
    } finally {
      captured.restore();
    }
  });

  it('logLevel() with an unknown level string is silently dropped (not in levelValues)', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'info',
        levels: { error: 0, warn: 1, info: 2 },
      },
    });

    const captured = captureOutput();
    try {
      // 'phantom' is not in levels → shouldLog returns false → nothing emitted
      await logger.logLevel('phantom', 'should be dropped');
      expect(captured.lines.join('')).not.toContain('should be dropped');
    } finally {
      captured.restore();
    }
  });

  it('custom level appears correctly in log output text', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'payment',
        levels: { error: 0, warn: 1, info: 2, payment: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('payment', 'order completed');
      const out = captured.lines.join('');
      expect(out).toContain('[PAYMENT]');
      expect(out).toContain('order completed');
    } finally {
      captured.restore();
    }
  });

  it('setLevel to a custom level correctly updates the filter threshold', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'error', // start strict
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await logger.logLevel('kafka', 'before setLevel');
      expect(captured.lines.join('')).not.toContain('before setLevel');

      logger.setLevel('kafka');
      await logger.logLevel('kafka', 'after setLevel');
      expect(captured.lines.join('')).toContain('after setLevel');
    } finally {
      captured.restore();
    }
  });
});

// ── 4. createLogger factory — custom method + data ────────────────────────────

describe('createLogger factory — full custom level flow', () => {
  it('custom method logs message + structured data', async () => {
    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'payment',
        levels: { error: 0, warn: 1, info: 2, payment: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await (logger as any).payment('charge processed', {
        amount: 99.99,
        currency: 'USD',
        txnId: 'txn_abc',
      });
      const out = captured.lines.join('');
      expect(out).toContain('charge processed');
      expect(out).toContain('txn_abc');
      expect(out).toContain('99.99');
    } finally {
      captured.restore();
    }
  });

  it('multiple custom levels all emit independently', async () => {
    const logger = createLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'audit',
        levels: { error: 0, warn: 1, info: 2, kafka: 3, audit: 4 },
      },
    });

    const captured = captureOutput();
    try {
      await (logger as any).kafka('kafka fired');
      await (logger as any).audit('audit fired');
      const out = captured.lines.join('');
      expect(out).toContain('kafka fired');
      expect(out).toContain('audit fired');
    } finally {
      captured.restore();
    }
  });

  it('child logger inherits custom level methods from parent config', async () => {
    const parent = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
      },
    });

    const child = parent.child('KafkaService') as any;
    expect(typeof child.kafka).toBe('function');

    const captured = captureOutput();
    try {
      await child.kafka('child kafka message');
      expect(captured.lines.join('')).toContain('child kafka message');
    } finally {
      captured.restore();
    }
  });
});

// ── 5. Regression: built-in levels unaffected by custom level additions ────────

describe('Regression — built-in levels unaffected by custom level additions', () => {
  it('info/warn/error still work after adding custom levels', async () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
      },
    });

    const captured = captureOutput();
    try {
      await logger.info('info msg');
      await logger.warn('warn msg');
      const out = captured.lines.join('');
      expect(out).toContain('info msg');
      expect(out).toContain('warn msg');
    } finally {
      captured.restore();
    }
  });

  it('built-in level colors are not disrupted by adding custom levels', () => {
    const logger = new LogixiaLogger({
      ...BASE_CONFIG_COLOR,
      levelOptions: {
        level: 'kafka',
        levels: { error: 0, warn: 1, info: 2, kafka: 3 },
        colors: { error: 'red', warn: 'yellow', info: 'blue' },
      },
    }) as any;

    // info should be blue (\x1b[34m)
    const infoFormatted: string = logger._formattedLevels.get('info') ?? '';
    expect(infoFormatted).toContain(`${ESC}[34m`);

    // error should be red (\x1b[31m)
    const errorFormatted: string = logger._formattedLevels.get('error') ?? '';
    expect(errorFormatted).toContain(`${ESC}[31m`);
  });

  it('LogixiaLoggerService built-in log/warn/error still work after custom level setup', async () => {
    const svc = new LogixiaLoggerService({
      levelOptions: {
        // Explicitly set level so NODE_ENV=test adaptive default (warn) doesn't suppress info/log
        level: 'debug',
        levels: { error: 0, warn: 1, log: 2, debug: 3, verbose: 4, payment: 5 },
      },
    });

    const captured = captureOutput();
    try {
      svc.log('standard log message');
      await new Promise((r) => setTimeout(r, 10)); // let async fire-and-forget settle
      expect(captured.lines.join('')).toContain('standard log message');
    } finally {
      captured.restore();
    }
  });
});
