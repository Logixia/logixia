/**
 * The four real analytics transports, constructed the way users construct them.
 * Before, the base constructor called initialize() before the subclass had set
 * its config, so every one of these rejected unhandled at startup and also sent
 * a test event to the customer's account.
 */

import type { TransportLogEntry } from '../../types/transport.types';
import type { AnalyticsTransport } from '../analytics.transport';
import { DataDogTransport } from '../datadog.transport';
import { GoogleAnalyticsTransport } from '../google-analytics.transport';
import { MixpanelTransport } from '../mixpanel.transport';
import { SegmentTransport } from '../segment.transport';

const entry: TransportLogEntry = {
  timestamp: new Date('2026-01-01T00:00:00.000Z'),
  level: 'info',
  message: 'checkout completed',
  data: { userId: 'u_42', orderId: 7 },
};

const providers: Array<[string, () => AnalyticsTransport, () => AnalyticsTransport]> = [
  [
    'segment',
    () => new SegmentTransport({ apiKey: 'k', writeKey: 'wk', batchSize: 1 }),
    () => new SegmentTransport({ apiKey: 'k', writeKey: '', batchSize: 1 }),
  ],
  [
    'datadog',
    () => new DataDogTransport({ apiKey: 'dd', batchSize: 1 }),
    () => new DataDogTransport({ apiKey: '', batchSize: 1 }),
  ],
  [
    'mixpanel',
    () => new MixpanelTransport({ apiKey: 'k', token: 'tok', batchSize: 1 }),
    () => new MixpanelTransport({ apiKey: 'k', token: '', batchSize: 1 }),
  ],
  [
    'google-analytics',
    () =>
      new GoogleAnalyticsTransport({
        apiKey: 'k',
        measurementId: 'G-1',
        apiSecret: 's',
        batchSize: 1,
      }),
    () =>
      new GoogleAnalyticsTransport({
        apiKey: 'k',
        measurementId: '',
        apiSecret: 's',
        batchSize: 1,
      }),
  ],
];

describe.each(providers)('%s transport', (_name, create, createMisconfigured) => {
  let fetchMock: jest.Mock;
  let unhandled: unknown[];
  const onUnhandled = (reason: unknown): void => {
    unhandled.push(reason);
  };
  const realFetch = globalThis.fetch;

  beforeEach(() => {
    unhandled = [];
    process.on('unhandledRejection', onUnhandled);
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    fetchMock = jest.fn(async () => ({
      ok: true,
      status: 200,
      statusText: 'OK',
      json: async () => ({}),
      text: async () => '1', // Mixpanel answers 1 on success
    }));
    globalThis.fetch = fetchMock as unknown as typeof fetch;
  });

  afterEach(() => {
    process.off('unhandledRejection', onUnhandled);
    delete process.env.LOGIXIA_SILENT_INTERNAL;
    globalThis.fetch = realFetch;
  });

  const settle = (): Promise<void> => new Promise((resolve) => setImmediate(resolve));

  it('constructs without a rejection and without sending anything', async () => {
    const transport = create();
    await settle();

    expect(unhandled).toEqual([]);
    expect(fetchMock).not.toHaveBeenCalled();
    await transport.close();
  });

  it('sends the real entry and no startup test event', async () => {
    const transport = create();
    await transport.write(entry);
    await transport.close();

    expect(fetchMock).toHaveBeenCalled();
    const bodies = fetchMock.mock.calls.map(([, init]) => String(init?.body ?? ''));
    expect(bodies.some((b) => b.includes('checkout completed'))).toBe(true);
    expect(bodies.join('\n')).not.toMatch(/logitron_test|Logixia Test|logitron\.test|test-user/);
    expect(unhandled).toEqual([]);
  });

  it('fails writes with the config error instead of crashing at startup', async () => {
    const transport = createMisconfigured();
    await settle();
    expect(unhandled).toEqual([]);

    await expect(transport.write(entry)).rejects.toThrow(/required/i);
    await expect(transport.write(entry)).rejects.toThrow(/required/i);
    expect(fetchMock).not.toHaveBeenCalled();
    await transport.close();
  });
});
