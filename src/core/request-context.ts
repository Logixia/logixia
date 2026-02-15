/**
 * Request context tracking for Logitron
 */

import { RequestContext, HttpRequest, HttpResponse } from "../types";
import {
  generateTraceId,
  getCurrentTraceId,
  setTraceId,
} from "../utils/trace.utils";

export class RequestContextManager {
  private static contexts = new Map<string, RequestContext>();

  /**
   * Create a new request context
   */
  static createContext(request: HttpRequest, traceId?: string): RequestContext {
    const requestId = generateTraceId();
    const contextTraceId = traceId || getCurrentTraceId() || generateTraceId();

    const context: RequestContext = {
      requestId,
      traceId: contextTraceId,
      startTime: Date.now(),
      request,
      ...(request.userAgent && { userAgent: request.userAgent }),
      ...(request.ip && { ip: request.ip }),
    };

    this.contexts.set(requestId, context);

    // Set trace ID in async context
    setTraceId(contextTraceId, {
      requestId,
      method: request.method,
      url: request.url,
    });

    return context;
  }

  /**
   * Update request context with response data
   */
  static updateContext(
    requestId: string,
    response?: HttpResponse,
    error?: Error,
  ): RequestContext | undefined {
    const context = this.contexts.get(requestId);
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
   * Get request context by ID
   */
  static getContext(requestId: string): RequestContext | undefined {
    return this.contexts.get(requestId);
  }

  /**
   * Remove request context (cleanup)
   */
  static removeContext(requestId: string): boolean {
    return this.contexts.delete(requestId);
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

    for (const [requestId, context] of this.contexts.entries()) {
      if (context.endTime && now - context.endTime > maxAgeMs) {
        this.contexts.delete(requestId);
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
    query?: Record<string, any>;
    params?: Record<string, any>;
    body?: any;
    ip?: string;
    userAgent?: string;
  } = {},
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
  body?: any,
  contentLength?: number,
): HttpResponse {
  return {
    statusCode,
    headers,
    ...(body !== undefined && { body }),
    ...(contentLength !== undefined && { contentLength }),
    timestamp: Date.now(),
  };
}
