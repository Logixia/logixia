/**
 * Exercises the OTel bridge against the REAL `@opentelemetry/api` + SDK (no mocks).
 *
 * Regression: the bridge read `api.trace.TraceFlags`, which does not exist in the
 * real API (`TraceFlags` is a root export), so the throw was swallowed and no
 * trace context was ever injected into log entries.
 */

import { context, trace } from '@opentelemetry/api';
import { AsyncLocalStorageContextManager } from '@opentelemetry/context-async-hooks';
import { BasicTracerProvider } from '@opentelemetry/sdk-trace-base';

import { createLogger } from '../../index';
import type { ITransport, TransportLogEntry } from '../../types/transport.types';
import {
  disableOtelBridge,
  getActiveOtelContext,
  getOtelMetaFields,
  initOtelBridge,
} from '../otel';

const provider = new BasicTracerProvider();
const tracer = provider.getTracer('logixia-test');
const contextManager = new AsyncLocalStorageContextManager().enable();

beforeAll(() => {
  context.setGlobalContextManager(contextManager);
});

afterAll(async () => {
  context.disable();
  contextManager.disable();
  await provider.shutdown();
});

afterEach(() => {
  disableOtelBridge();
});

describe('OTel bridge with the real @opentelemetry/api', () => {
  it('returns undefined outside a span', () => {
    expect(getActiveOtelContext()).toBeUndefined();
  });

  it('reads the active span context', () => {
    tracer.startActiveSpan('work', (span) => {
      const sc = span.spanContext();
      expect(getActiveOtelContext()).toEqual({
        traceId: sc.traceId,
        spanId: sc.spanId,
        traceFlags: 1,
        isSampled: true,
      });
      expect(getOtelMetaFields({ traceIdField: 'trace_id' })).toEqual({
        trace_id: sc.traceId,
        spanId: sc.spanId,
        traceFlags: 1,
      });
      span.end();
    });
  });

  it('honours sampledOnly for an unsampled span', () => {
    const unsampled = trace.wrapSpanContext({
      traceId: '0af7651916cd43dd8448eb211c80319c',
      spanId: 'b7ad6b7169203331',
      traceFlags: 0,
    });
    context.with(trace.setSpan(context.active(), unsampled), () => {
      expect(getActiveOtelContext()?.isSampled).toBe(false);
      expect(getActiveOtelContext({ sampledOnly: true })).toBeUndefined();
    });
  });

  it('injects trace_id/span_id/flags into the log entry the logger emits', async () => {
    const entries: TransportLogEntry[] = [];
    const sink: ITransport = {
      name: 'sink',
      write(entry) {
        entries.push(entry);
      },
    };
    const logger = createLogger({
      appName: 'otel-real',
      transports: { custom: [sink] },
    });
    initOtelBridge({ traceIdField: 'trace_id', spanIdField: 'span_id', traceFlagsField: 'flags' });

    let expected: { traceId: string; spanId: string } | undefined;
    await tracer.startActiveSpan('request', async (span) => {
      expected = span.spanContext();
      await logger.info('inside span', { orderId: 'ord_1' });
      span.end();
    });
    await logger.info('outside span');
    await logger.close();

    expect(expected).toBeDefined();
    const inside = entries.find((e) => e.message === 'inside span');
    expect(inside?.data).toMatchObject({
      trace_id: expected?.traceId,
      span_id: expected?.spanId,
      flags: 1,
      orderId: 'ord_1',
    });
    const outside = entries.find((e) => e.message === 'outside span');
    expect(outside?.data?.['trace_id']).toBeUndefined();
  });
});
