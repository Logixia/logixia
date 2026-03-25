/**
 * Request context tracking for Logitron
 */

import type { HttpRequest, HttpResponse, RequestContext } from '../types';
import { TraceContext } from '../utils/trace.utils';

export class RequestContextManager {
  private static contexts = new Map<string, RequestContext>();

  /**
   * Create a new request context
   */
  static createContext(request: HttpRequest, traceId?: string): RequestContext {
    const ctx = TraceContext.instance;
    const contextTraceId = traceId || ctx.getCurrentTraceId() || ctx.generate();

    const context: RequestContext = {
      traceId: contextTraceId,
      startTime: Date.now(),
      request,
      ...(request.userAgent && { userAgent: request.userAgent }),
      ...(request.ip && { ip: request.ip }),
    };

    this.contexts.set(contextTraceId, context);

    // Set trace ID in async context
    TraceContext.instance.setTraceId(contextTraceId, {
      method: request.method,
      url: request.url,
    });

    return context;
  }

  /**
   * Update request context with response data
   */
  static updateContext(
    traceId: string,
    response?: HttpResponse,
    error?: Error
  ): RequestContext | undefined {
    const context = this.contexts.get(traceId);
    if (!context) {
      return undefined;
    }

    const endTime = Date.now();
    context.endTime = endTime;
    context.duration = endTime - context.startTime;

    if (response) {
      context.response = response;
    }

    if (error) {
      context.error = error;
    }

    return context;
  }

  /**
   * Get request context by trace ID
   */
  static getContext(traceId: string): RequestContext | undefined {
    return this.contexts.get(traceId);
  }

  /**
   * Remove request context (cleanup)
   */
  static removeContext(traceId: string): boolean {
    return this.contexts.delete(traceId);
  }

  /**
   * Get all active contexts
   */
  static getAllContexts(): RequestContext[] {
    return Array.from(this.contexts.values());
  }

  /**
   * Clear all contexts (useful for testing)
   */
  static clearAll(): void {
    this.contexts.clear();
  }

  /**
   * Get context statistics
   */
  static getStats(): {
    activeContexts: number;
    averageDuration: number;
    completedRequests: number;
  } {
    const contexts = Array.from(this.contexts.values());
    const completedContexts = contexts.filter((ctx) => ctx.endTime);

    const averageDuration =
      completedContexts.length > 0
        ? completedContexts.reduce((sum, ctx) => sum + (ctx.duration || 0), 0) /
          completedContexts.length
        : 0;

    return {
      activeContexts: contexts.length,
      averageDuration,
      completedRequests: completedContexts.length,
    };
  }

  /**
   * Cleanup old completed contexts (older than specified time)
   */
  static cleanup(maxAgeMs: number = 300000): number {
    // 5 minutes default
    const now = Date.now();
    let cleaned = 0;

    for (const [traceId, context] of this.contexts.entries()) {
      if (context.endTime && now - context.endTime > maxAgeMs) {
        this.contexts.delete(traceId);
        cleaned++;
      }
    }

    return cleaned;
  }
}

/**
 * Helper function to create HTTP request object from various sources
 */
export function createHttpRequest(
  method: string,
  url: string,
  headers: Record<string, string | string[]> = {},
  options: {
    query?: Record<string, unknown>;
    params?: Record<string, unknown>;
    body?: unknown;
    ip?: string;
    userAgent?: string;
  } = {}
): HttpRequest {
  return {
    method: method.toUpperCase(),
    url,
    headers,
    ...(options.query && { query: options.query }),
    ...(options.params && { params: options.params }),
    ...(options.body !== undefined && { body: options.body }),
    ...(options.ip && { ip: options.ip }),
    ...(options.userAgent && { userAgent: options.userAgent }),
    timestamp: Date.now(),
  };
}

/**
 * Helper function to create HTTP response object
 */
export function createHttpResponse(
  statusCode: number,
  headers: Record<string, string | string[]> = {},
  body?: unknown,
  contentLength?: number
): HttpResponse {
  return {
    statusCode,
    headers,
    ...(body !== undefined && { body }),
    ...(contentLength !== undefined && { contentLength }),
    timestamp: Date.now(),
  };
}
