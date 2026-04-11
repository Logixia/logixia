/** @format */

import type { CallHandler, ExecutionContext, NestInterceptor } from '@nestjs/common';
import { Injectable } from '@nestjs/common';
import { EMPTY, Observable } from 'rxjs';

import type { TraceIdConfig } from '../types';
import { extractTraceId, TraceContext } from '../utils/trace.utils';
import { LogixiaLoggerModule } from './logitron-logger.module';

/**
 * Observable counters exposed for monitoring Kafka consumer trace hygiene.
 *
 * Usage:
 *   import { KafkaTraceInterceptor } from 'logixia/nest';
 *   setInterval(() => {
 *     myMetrics.gauge('kafka.trace.dropped', KafkaTraceInterceptor.metrics.dropped);
 *   }, 10_000);
 */
export interface KafkaTraceMetrics {
  /** Messages processed where a traceId was successfully resolved (body/header/ALS). */
  accepted: number;
  /** Messages handled without any traceId — `requireTraceId: false`. */
  acceptedWithoutTrace: number;
  /** Messages dropped because `requireTraceId: true` and no traceId was found. */
  dropped: number;
}

@Injectable()
export class KafkaTraceInterceptor implements NestInterceptor {
  /**
   * Process-wide counters. Readable from anywhere — scrape into your metrics
   * system (Prometheus, Datadog, CloudWatch) on an interval.
   */
  static readonly metrics: KafkaTraceMetrics = {
    accepted: 0,
    acceptedWithoutTrace: 0,
    dropped: 0,
  };

  /** Reset counters (tests). */
  static resetMetrics(): void {
    KafkaTraceInterceptor.metrics.accepted = 0;
    KafkaTraceInterceptor.metrics.acceptedWithoutTrace = 0;
    KafkaTraceInterceptor.metrics.dropped = 0;
  }

  private readonly ctx = TraceContext.instance;

  /**
   * @param config        - TraceIdConfig options (extractor keys, contextKey, etc.)
   * @param requireTraceId - When true, messages with no traceId are silently skipped
   *                         (EMPTY Observable — message is ack'd, consumer stays alive).
   *                         A WARN is logged AND `KafkaTraceInterceptor.metrics.dropped`
   *                         increments so the missing traceId is observable end-to-end.
   *                         Default: false (handler runs without trace context).
   */
  constructor(
    private readonly config?: TraceIdConfig,
    private readonly requireTraceId: boolean = false
  ) {
    this.config = {
      enabled: true,
      contextKey: 'traceId',
      extractor: {
        body: ['traceId', 'trace_id', 'x-trace-id'],
        header: ['x-trace-id', 'trace-id'],
      },
      ...config,
    };
  }

  // eslint-disable-next-line @typescript-eslint/no-explicit-any -- NestJS interceptor interface requires Observable<any>
  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    if (!this.config?.enabled) {
      return next.handle();
    }

    const rpcContext = context.switchToRpc();
    const data = rpcContext.getData();
    const rpcData = rpcContext.getContext();

    let traceId: string | undefined;

    if (this.config.extractor) {
      traceId = extractTraceId(
        { body: data, headers: rpcData?.headers ?? {}, query: {}, params: {} },
        this.config.extractor
      );
    }

    if (!traceId) {
      traceId = this.ctx.getCurrentTraceId();
    }

    if (!traceId) {
      if (this.requireTraceId) {
        // Warn via global logger (set when LogixiaLoggerModule boots) and ack
        // the message by returning EMPTY — consumer stays alive, no retry loop.
        KafkaTraceInterceptor.metrics.dropped++;
        LogixiaLoggerModule.getGlobalLogger()?.warn(
          `[KafkaTraceInterceptor] Missing traceId on topic "${rpcData?.topic}" — message skipped.`
        );
        return EMPTY;
      }
      KafkaTraceInterceptor.metrics.acceptedWithoutTrace++;
      return next.handle();
    }

    KafkaTraceInterceptor.metrics.accepted++;

    const kafkaContext = {
      messageType: 'kafka',
      topic: rpcData?.topic,
      partition: rpcData?.partition,
      offset: rpcData?.offset,
      key: rpcData?.key,
      timestamp: rpcData?.timestamp,
    };

    return new Observable((subscriber) => {
      this.ctx.run(
        traceId!,
        () => {
          next.handle().subscribe({
            next: (value) => subscriber.next(value),
            error: (err) => subscriber.error(err),
            complete: () => subscriber.complete(),
          });
        },
        kafkaContext
      );
    });
  }
}
