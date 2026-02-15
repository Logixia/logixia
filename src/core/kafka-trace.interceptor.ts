/** @format */

import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
} from "@nestjs/common";
import { Observable } from "rxjs";
import {
  runWithTraceId,
  getCurrentTraceId,
  extractTraceId,
} from "../utils/trace.utils";
import type { TraceIdConfig } from "../types";

@Injectable()
export class KafkaTraceInterceptor implements NestInterceptor {
  constructor(private readonly config?: TraceIdConfig) {
    this.config = {
      enabled: true,
      contextKey: "traceId",
      extractor: {
        body: ["traceId", "trace_id", "x-trace-id"],
        header: ["x-trace-id", "trace-id"],
      },
      ...config,
    };
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // Check if trace ID is enabled
    if (!this.config?.enabled) {
      return next.handle();
    }

    const rpcContext = context.switchToRpc();
    const data = rpcContext.getData();
    const rpcData = rpcContext.getContext();

    let traceId: string | undefined;

    // Try to extract existing trace ID using extractor
    if (this.config.extractor) {
      // Create a request-like object for extractTraceId
      const requestLike = {
        body: data,
        headers: rpcData?.headers || {},
        query: {},
        params: {},
      };
      traceId = extractTraceId(requestLike, this.config.extractor);
    }

    // Only use current trace ID if no extraction happened and we have one
    if (!traceId) {
      traceId = getCurrentTraceId();
    }

    // If still no trace ID and enabled, skip (don't generate)
    if (!traceId) {
      return next.handle();
    }

    // Set up Kafka-specific context data
    const kafkaContext = {
      messageType: "kafka",
      topic: rpcData?.topic,
      partition: rpcData?.partition,
      offset: rpcData?.offset,
      key: rpcData?.key,
      timestamp: rpcData?.timestamp,
    };

    // Run the handler with trace ID context
    return new Observable((subscriber) => {
      runWithTraceId(
        traceId!,
        () => {
          next.handle().subscribe({
            next: (value) => subscriber.next(value),
            error: (err) => subscriber.error(err),
            complete: () => subscriber.complete(),
          });
        },
        kafkaContext,
      );
    });
  }
}
