/**
 * Inside the context middleware the ALS payload carries `traceId`, which is the
 * same value as the entry's top-level `traceId`. The JSON console line must not
 * emit it a second time as `data_traceId`.
 */

import { createExpressContextMiddleware, createLogger } from '../../index';
import { mergeCoreFields } from '../../transports/entry-fields';

describe('mergeCoreFields traceId de-duplication', () => {
  it('drops a payload traceId equal to the core traceId', () => {
    expect(mergeCoreFields({ traceId: 't1' }, { traceId: 't1', a: 1 })).toEqual({
      traceId: 't1',
      a: 1,
    });
  });

  it('keeps renaming a payload traceId that differs', () => {
    expect(mergeCoreFields({ traceId: 't1' }, { traceId: 't2' })).toEqual({
      traceId: 't1',
      data_traceId: 't2',
    });
  });

  it('does not drop a payload traceId when the core one is absent', () => {
    expect(mergeCoreFields({ traceId: undefined }, { traceId: 't2' })).toEqual({
      traceId: undefined,
      data_traceId: 't2',
    });
  });
});

describe('console JSON inside the context middleware', () => {
  it('emits a single traceId and no data_traceId', async () => {
    const lines: string[] = [];
    const outSpy = jest.spyOn(process.stdout, 'write').mockImplementation((c: unknown) => {
      lines.push(String(c));
      return true;
    });
    try {
      const logger = createLogger({
        appName: 'dup',
        transports: { console: { format: 'json' } },
      });
      const middleware = createExpressContextMiddleware();
      await new Promise<void>((resolve, reject) => {
        middleware({ headers: { 'x-trace-id': 'abc-123' } }, {}, () => {
          logger.info('in request').then(() => resolve(), reject);
        });
      });
      await logger.close();

      const line = lines.find((l) => l.includes('in request'));
      expect(line).toBeDefined();
      const parsed = JSON.parse(line as string) as Record<string, unknown>;
      expect(parsed['traceId']).toBe('abc-123');
      expect(parsed).not.toHaveProperty('data_traceId');
      expect(line?.match(/abc-123/g)).toHaveLength(1);
    } finally {
      outSpy.mockRestore();
    }
  });
});
