/**
 * A BigInt or a circular reference in a payload used to make logger.info()
 * reject and lose the line, because formatting went through JSON.stringify.
 */

import { createLogger } from '../logitron-logger';

function captureStdout(): { lines: string[]; restore(): void } {
  const lines: string[] = [];
  const original = process.stdout.write.bind(process.stdout);
  (process.stdout as NodeJS.WriteStream).write = (chunk: unknown) => {
    lines.push(String(chunk ?? ''));
    return true;
  };
  return {
    lines,
    restore: () => {
      (process.stdout as NodeJS.WriteStream).write = original as typeof process.stdout.write;
    },
  };
}

function awkwardPayload(): Record<string, unknown> {
  const req: Record<string, unknown> = { id: 10n };
  req.self = req;
  return { req };
}

describe('logger with payloads JSON.stringify rejects', () => {
  it.each([
    ['text', {}],
    ['json', { format: { json: true } }],
  ])('writes the line in %s mode', async (_mode, extra) => {
    const logger = createLogger({ appName: 'app', environment: 'test', ...extra });
    const cap = captureStdout();
    try {
      await expect(logger.info('order placed', awkwardPayload())).resolves.toBeUndefined();
    } finally {
      cap.restore();
    }

    const out = cap.lines.join('');
    expect(out).toContain('order placed');
    expect(out).toContain('"id":"10"');
    expect(out).toContain('[Circular]');
  });
});
