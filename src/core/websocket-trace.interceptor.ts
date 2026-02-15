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
export class WebSocketTraceInterceptor implements NestInterceptor {
  constructor(private readonly config?: TraceIdConfig) {
    this.config = {
      enabled: true,
      contextKey: "traceId",
      extractor: {
        body: ["traceId", "trace_id", "x-trace-id"],
        header: ["x-trace-id", "trace-id"],
        query: ["traceId", "trace_id"],
      },
      ...config,
    };
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    // Check if trace ID is enabled
    if (!this.config?.enabled) {
      return next.handle();
    }

    const wsContext = context.switchToWs();
    const data = wsContext.getData();
    const client = wsContext.getClient();

    let traceId: string | undefined;

    // Try to extract existing trace ID using extractor
    if (this.config.extractor) {
      // Create a request-like object for extractTraceId
      const requestLike = {
        body: data,
        headers: client?.handshake?.headers || {},
        query: client?.handshake?.query || {},
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

    // Set up WebSocket-specific context data
    const wsContextData = {
      messageType: "websocket",
      event: data?.event,
      socketId: client?.id,
      rooms: client?.rooms ? Array.from(client.rooms) : [],
      clientAddress: client?.handshake?.address,
    };

    // Run the handler with trace ID context
    return new Observable((observer) => {
      runWithTraceId(
        traceId!,
        () => {
          const result = next.handle();
          result.subscribe({
            next: (value) => observer.next(value),
            error: (err) => observer.error(err),
            complete: () => observer.complete(),
          });
        },
        wsContextData,
      );
    });
  }
}
