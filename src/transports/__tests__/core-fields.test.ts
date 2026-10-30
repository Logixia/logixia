/**
 * A user payload must never replace the fields a transport owns (level,
 * message, timestamp, service, token, _aws...). Colliding payload keys are kept
 * under a `data_` prefix instead.
 */

import type { TransportLogEntry } from '../../types/transport.types';
import { CloudWatchTransport } from '../cloudwatch.transport';
import { ConsoleTransport } from '../console.transport';
import { DataDogTransport } from '../datadog.transport';
import { mergeCoreFields } from '../entry-fields';
import { GCPTransport } from '../gcp.transport';
import { GoogleAnalyticsTransport } from '../google-analytics.transport';
import { MixpanelTransport } from '../mixpanel.transport';
import { SegmentTransport } from '../segment.transport';

const spoof: TransportLogEntry = {
  timestamp: new Date('2026-01-01T00:00:00.000Z'),
  level: 'error',
  message: 'real message',
  context: 'Ctx',
  traceId: 'trace-1',
  data: {
    level: 'debug',
    message: 'nothing to see',
    timestamp: '2020-01-01T00:00:00.000Z',
    context: 'fake',
    traceId: 'fake-trace',
    appName: 'fake-app',
    user: 'someone',
  },
};

describe('mergeCoreFields', () => {
  it('keeps core values and moves colliding keys under data_', () => {
    const out = mergeCoreFields(
      { level: 'error', context: undefined },
      { level: 'x', context: 'c', ok: 1 }
    );
    expect(out).toEqual({
      level: 'error',
      context: undefined,
      data_level: 'x',
      data_context: 'c',
      ok: 1,
    });
  });

  it('leaves a payload data_ key where it is and renames around it', () => {
    const forward = mergeCoreFields({ level: 'error' }, { level: 'a', data_level: 'b' });
    const reverse = mergeCoreFields({ level: 'error' }, { data_level: 'b', level: 'a' });
    expect(forward).toEqual({ level: 'error', data_level: 'b', data_data_level: 'a' });
    expect(reverse).toEqual(forward);
  });

  it('does not rename inherited property names', () => {
    const out = mergeCoreFields(
      { level: 'error' },
      JSON.parse('{"constructor":1,"toString":2,"valueOf":3}')
    );
    expect(out).toMatchObject({ constructor: 1, toString: 2, valueOf: 3 });
    expect(out).not.toHaveProperty('data_constructor');
  });

  it('skips __proto__', () => {
    const out = mergeCoreFields({ a: 1 }, JSON.parse('{"__proto__":{"x":1},"b":2}'));
    expect(Object.getPrototypeOf(out)).toBe(Object.prototype);
    expect(out).toEqual({ a: 1, b: 2 });
  });
});

describe('ConsoleTransport json', () => {
  it('emits the real level and message', () => {
    const writes: string[] = [];
    const spy = jest.spyOn(process.stderr, 'write').mockImplementation((chunk: unknown) => {
      writes.push(String(chunk));
      return true;
    });
    try {
      new ConsoleTransport({ format: 'json' }).write(spoof);
    } finally {
      spy.mockRestore();
    }
    const out = JSON.parse(writes.join(''));
    expect(out).toMatchObject({
      level: 'error',
      message: 'real message',
      timestamp: '2026-01-01T00:00:00.000Z',
      context: 'Ctx',
      traceId: 'trace-1',
      user: 'someone',
      data_level: 'debug',
      data_message: 'nothing to see',
    });
  });
});

describe('GCPTransport', () => {
  it('keeps message, appName and context authoritative', () => {
    const t = new GCPTransport({ projectId: 'p', flushIntervalMs: 999_999 });
    const built = (
      t as unknown as {
        buildLogEntry(e: TransportLogEntry): { jsonPayload: Record<string, unknown> };
      }
    ).buildLogEntry({ ...spoof, appName: 'real-app' });
    expect(built.jsonPayload).toMatchObject({
      message: 'real message',
      appName: 'real-app',
      context: 'Ctx',
      data_message: 'nothing to see',
      data_appName: 'fake-app',
    });
    void t.close();
  });
});

describe('CloudWatch EMF', () => {
  const emf = (config: Record<string, unknown>, data: Record<string, unknown>) => {
    const t = new CloudWatchTransport({
      logGroupName: '/g',
      flushIntervalMs: 999_999,
      emf: true,
      ...config,
    });
    const out = JSON.parse(
      (t as unknown as { toEmf(e: TransportLogEntry): string }).toEmf({ ...spoof, data })
    ) as Record<string, any>;
    void t.close();
    return out;
  };

  it('does not let the payload replace _aws, level or message', () => {
    const out = emf(
      {},
      {
        _aws: { CloudWatchMetrics: [{ Namespace: 'Evil', Metrics: [] }] },
        level: 'debug',
        message: 'x',
        n: 3,
      }
    );
    expect(out._aws.CloudWatchMetrics[0].Namespace).toBe('Logixia');
    expect(out.level).toBe('error');
    expect(out.message).toBe('real message');
    expect(out.data__aws).toBeDefined();
    expect(out._aws.CloudWatchMetrics[0].Metrics).toEqual([{ Name: 'n', Unit: 'None' }]);
  });

  it('publishes only the configured metrics when emfMetrics is set', () => {
    const out = emf({ emfMetrics: ['duration'] }, { duration: 5, userSuppliedCount: 9 });
    expect(out._aws.CloudWatchMetrics[0].Metrics).toEqual([{ Name: 'duration', Unit: 'None' }]);
    expect(out.userSuppliedCount).toBe(9);
  });

  it('caps metrics at the EMF limit of 100', () => {
    const data: Record<string, number> = {};
    for (let i = 0; i < 150; i += 1) data[`m${i}`] = i;
    const out = emf({}, data);
    expect(out._aws.CloudWatchMetrics[0].Metrics).toHaveLength(100);
  });
});

describe('analytics providers', () => {
  const realFetch = globalThis.fetch;
  let bodies: any[];

  beforeEach(() => {
    bodies = [];
    process.env.LOGIXIA_SILENT_INTERNAL = '1';
    globalThis.fetch = jest.fn(async (_url: unknown, init?: { body?: string }) => {
      bodies.push(JSON.parse(String(init?.body)));
      return {
        ok: true,
        status: 200,
        statusText: 'OK',
        text: async () => '1',
        json: async () => ({}),
      };
    }) as unknown as typeof fetch;
  });

  afterEach(() => {
    globalThis.fetch = realFetch;
    delete process.env.LOGIXIA_SILENT_INTERNAL;
  });

  it('datadog: service, env, version, logger, level and message win', async () => {
    const t = new DataDogTransport({
      apiKey: 'k',
      batchSize: 1,
      service: 'svc',
      env: 'prod',
      version: '1.2.3',
    });
    await t.write({
      ...spoof,
      data: {
        service: 'evil',
        env: 'evil',
        version: 'evil',
        logger: 'evil',
        host: 'evil',
        status: 'evil',
        ddtags: 'evil',
        ddsource: 'evil',
        hostname: 'evil',
        level: 'debug',
        message: 'x',
      },
    });
    await t.close();
    const log = (bodies[0].logs ?? bodies[0])[0] ?? bodies[0];
    expect(log).toMatchObject({
      service: 'svc',
      env: 'prod',
      version: '1.2.3',
      level: 'error',
      message: 'real message',
      logger: { name: 'logixia', thread_name: 'main' },
      data_service: 'evil',
      data_logger: 'evil',
      data_status: 'evil',
      data_ddtags: 'evil',
      data_ddsource: 'evil',
      data_hostname: 'evil',
    });
    expect(log.status).toBe('error');
    expect(log.ddtags).toBe('env:prod,service:svc,version:1.2.3');
    expect(log.ddsource).toBe('nodejs');
    expect(log.hostname).not.toBe('evil');
    expect(log.host).not.toBe('evil');
  });

  it('mixpanel: the configured token and distinct_id are sent', async () => {
    const t = new MixpanelTransport({ apiKey: 'k', token: 'real-token', batchSize: 1 });
    await t.write({
      ...spoof,
      data: { token: 'evil', distinct_id: 'evil', time: 1, $insert_id: 'evil' },
    });
    await t.close();
    const props = bodies[0][0].properties;
    expect(props.token).toBe('real-token');
    expect(props.distinct_id).toBe('anonymous');
    expect(props.$insert_id).not.toBe('evil');
    expect(props.level).toBe('error');
    expect(props.data_token).toBe('evil');
  });

  it('mixpanel: trackCustomEvent cannot override the token', async () => {
    const t = new MixpanelTransport({
      apiKey: 'k',
      token: 'real-token',
      batchSize: 1,
      enableEventTracking: true,
    });
    await t.trackCustomEvent('evt', { token: 'evil', distinct_id: 'evil' });
    await t.close();
    expect(bodies[0][0].properties.token).toBe('real-token');
    expect(bodies[0][0].properties.distinct_id).toBe('anonymous');
  });

  it('segment: level, message and logger are authoritative', async () => {
    const t = new SegmentTransport({ apiKey: 'k', writeKey: 'wk', batchSize: 1 });
    await t.write({ ...spoof, data: { logger: 'evil', level: 'debug', message: 'x' } });
    await t.close();
    expect(bodies[0].properties).toMatchObject({
      level: 'error',
      message: 'real message',
      logger: 'logixia',
    });
  });

  it('segment: userId comes from userId by default and never from id', async () => {
    const t = new SegmentTransport({ apiKey: 'k', writeKey: 'wk', batchSize: 1 });
    await t.write({ ...spoof, data: { id: 'row-1', user_id: 'u2' } });
    await t.write({ ...spoof, data: { userId: 'u1' } });
    await t.close();
    expect(bodies[0].userId).toBeUndefined();
    expect(bodies[1].userId).toBe('u1');
  });

  it('segment: userIdField selects the payload field', async () => {
    const t = new SegmentTransport({
      apiKey: 'k',
      writeKey: 'wk',
      batchSize: 1,
      userIdField: 'account',
    });
    await t.write({ ...spoof, data: { userId: 'u1', account: 'acct-9' } });
    await t.close();
    expect(bodies[0].userId).toBe('acct-9');
  });

  it('google analytics: core params cannot be overwritten by the payload', async () => {
    const t = new GoogleAnalyticsTransport({
      apiKey: 'k',
      measurementId: 'G-1',
      apiSecret: 's',
      batchSize: 1,
    });
    await t.write({
      ...spoof,
      data: {
        event_category: 'evil',
        log_level: 'evil',
        log_message: 'evil',
        trace_id: 'evil',
        custom_dimension_1: 'evil',
      },
    });
    await t.close();
    const params = bodies[0].events[0].params;
    expect(params).toMatchObject({
      event_category: 'Error',
      log_level: 'error',
      log_message: 'real message',
      trace_id: 'trace-1',
      custom_dimension_1: 'error',
      data_event_category: 'evil',
      data_log_level: 'evil',
    });
  });
});
