/** @format */

import { CallHandler, ExecutionContext, Injectable, NestInterceptor } from '@nestjs/common';
import { Observable } from 'rxjs';
import { runWithTraceId, getCurrentTraceId, extractTraceId } from '../utils/trace.utils';
import type { TraceIdConfig } from '../types';

/**
 * KafkaTraceInterceptor
 * 
 * Intercepts Kafka messages to extract or set a trace ID for observability.
 * It supports extracting trace ID from headers or body and runs the handler
 * within a trace context.
 */
@Injectable()
export class KafkaTraceInterceptor implements NestInterceptor {
  private readonly config: TraceIdConfig;

  constructor(config?: TraceIdConfig) {
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

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // If trace IDs are disabled, just continue
    if (!this.config?.enabled) return next.handle();

    const rpcContext = context.switchToRpc();
    const data = rpcContext.getData();
    const rpcData = rpcContext.getContext() || {}; // Default to empty object for safety

    let traceId: string | undefined;

    // Try to extract trace ID from request-like object
    if (this.config.extractor) {
      const requestLike = {
        body: data,
        headers: rpcData.headers || {},
        query: {},
        params: {},
      };
      traceId = extractTraceId(requestLike, this.config.extractor);
    }

    // Fallback to current trace ID if extraction failed
    traceId = traceId || getCurrentTraceId();

    // If no trace ID, continue without generating one
    if (!traceId) return next.handle();

    /**
     * Kafka-specific context info for tracing
     */
    const kafkaContext = {
      messageType: 'kafka',
      topic: rpcData.topic,
      partition: rpcData.partition,
      offset: rpcData.offset,
      key: rpcData.key,
      timestamp: rpcData.timestamp,
    };

    // Run handler within the trace ID context
    return new Observable((subscriber) => {
      runWithTraceId(traceId!, () => {
        next.handle().subscribe({
          next: (value) => subscriber.next(value),
          error: (err) => subscriber.error(err),
          complete: () => subscriber.complete(),
        });
      }, kafkaContext);
    });
  }
}
