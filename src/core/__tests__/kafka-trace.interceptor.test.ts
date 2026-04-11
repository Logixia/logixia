/**
 * KafkaTraceInterceptor unit tests
 *
 * Covers the behavior added in the production-readiness pass:
 *  - `requireTraceId: true` skips the message (EMPTY Observable) without
 *    crashing the consumer, increments `metrics.dropped`, and logs a warning.
 *  - `requireTraceId: false` lets a no-trace message through, increments
 *    `metrics.acceptedWithoutTrace`, and the handler runs.
 *  - When a traceId is resolved (body / header / ALS) it runs the handler
 *    inside an ALS-scoped context and increments `metrics.accepted`.
 */

import type { CallHandler, ExecutionContext } from '@nestjs/common';
import { firstValueFrom, of } from 'rxjs';

import { TraceContext } from '../../utils/trace.utils';
import { KafkaTraceInterceptor } from '../kafka-trace.interceptor';

// ── Helpers ──────────────────────────────────────────────────────────────────

function makeRpcContext(data: unknown, rpcData: unknown = {}): ExecutionContext {
  return {
    switchToRpc: () => ({
      getData: () => data,
      getContext: () => rpcData,
    }),
    getType: () => 'rpc',
  } as any;
}

function makeHandler(onCall?: () => void): { handler: CallHandler; wasCalled: () => boolean } {
  let called = false;
  const handler: CallHandler = {
    handle: () => {
      called = true;
      onCall?.();
      return of('handler ran');
    },
  };
  return { handler, wasCalled: () => called };
}

async function runInEmptyAls<T>(fn: () => Promise<T>): Promise<T> {
  // Ensure each assertion starts with an empty AsyncLocalStorage context so
  // the global test runner's async parent does not leak a traceId in.
  return new Promise<T>((resolve, reject) => {
    TraceContext.instance.storage.run({}, () => {
      fn().then(resolve).catch(reject);
    });
  });
}

beforeEach(() => {
  KafkaTraceInterceptor.resetMetrics();
});

// ── metrics surface ──────────────────────────────────────────────────────────

describe('KafkaTraceInterceptor.metrics', () => {
  it('starts at zero after resetMetrics()', () => {
    expect(KafkaTraceInterceptor.metrics.accepted).toBe(0);
    expect(KafkaTraceInterceptor.metrics.acceptedWithoutTrace).toBe(0);
    expect(KafkaTraceInterceptor.metrics.dropped).toBe(0);
  });
});

// ── requireTraceId: true + no trace ──────────────────────────────────────────

describe('KafkaTraceInterceptor — requireTraceId: true, missing trace', () => {
  it('returns EMPTY, does not call the handler, and increments dropped', async () => {
    await runInEmptyAls(async () => {
      const interceptor = new KafkaTraceInterceptor(undefined, true);
      const { handler, wasCalled } = makeHandler();

      const result$ = interceptor.intercept(
        makeRpcContext({}, { topic: 'order.created', headers: {} }),
        handler
      );
      const emitted = await firstValueFrom(result$, { defaultValue: '__empty__' });

      expect(wasCalled()).toBe(false);
      expect(emitted).toBe('__empty__');
      expect(KafkaTraceInterceptor.metrics.dropped).toBe(1);
      expect(KafkaTraceInterceptor.metrics.accepted).toBe(0);
      expect(KafkaTraceInterceptor.metrics.acceptedWithoutTrace).toBe(0);
    });
  });
});

// ── requireTraceId: false + no trace ─────────────────────────────────────────

describe('KafkaTraceInterceptor — requireTraceId: false, missing trace', () => {
  it('runs the handler and increments acceptedWithoutTrace', async () => {
    await runInEmptyAls(async () => {
      const interceptor = new KafkaTraceInterceptor(undefined, false);
      const { handler, wasCalled } = makeHandler();

      const result$ = interceptor.intercept(
        makeRpcContext({}, { topic: 'order.created', headers: {} }),
        handler
      );
      const emitted = await firstValueFrom(result$);

      expect(wasCalled()).toBe(true);
      expect(emitted).toBe('handler ran');
      expect(KafkaTraceInterceptor.metrics.acceptedWithoutTrace).toBe(1);
      expect(KafkaTraceInterceptor.metrics.dropped).toBe(0);
    });
  });
});

// ── traceId resolved ─────────────────────────────────────────────────────────

describe('KafkaTraceInterceptor — resolves traceId from body', () => {
  it('runs the handler, scopes ALS, and increments accepted', async () => {
    await runInEmptyAls(async () => {
      const interceptor = new KafkaTraceInterceptor(undefined, true);
      let observedInHandler: string | undefined;
      const { handler } = makeHandler(() => {
        observedInHandler = TraceContext.instance.getCurrentTraceId();
      });

      const result$ = interceptor.intercept(
        makeRpcContext({ traceId: 'body-trace-1' }, { topic: 'order.created', headers: {} }),
        handler
      );
      await firstValueFrom(result$);

      expect(observedInHandler).toBe('body-trace-1');
      expect(KafkaTraceInterceptor.metrics.accepted).toBe(1);
      expect(KafkaTraceInterceptor.metrics.dropped).toBe(0);
      expect(KafkaTraceInterceptor.metrics.acceptedWithoutTrace).toBe(0);
    });
  });

  it('resolves traceId from Kafka message headers when body is empty', async () => {
    await runInEmptyAls(async () => {
      const interceptor = new KafkaTraceInterceptor(undefined, true);
      let observedInHandler: string | undefined;
      const { handler } = makeHandler(() => {
        observedInHandler = TraceContext.instance.getCurrentTraceId();
      });

      const result$ = interceptor.intercept(
        makeRpcContext({}, { topic: 'order.created', headers: { 'x-trace-id': 'header-trace-2' } }),
        handler
      );
      await firstValueFrom(result$);

      expect(observedInHandler).toBe('header-trace-2');
      expect(KafkaTraceInterceptor.metrics.accepted).toBe(1);
    });
  });
});
