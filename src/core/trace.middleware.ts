/**
 * Trace ID middleware for NestJS integration
 */

import type { NestMiddleware } from '@nestjs/common';
import { Injectable, Optional } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

import type { TraceIdConfig } from '../types';
import { extractTraceId, generateTraceId, runWithTraceId } from '../utils/trace.utils';

// Extend Express Request interface — requires namespace to augment Express typings
/* eslint-disable @typescript-eslint/no-namespace */
declare global {
  namespace Express {
    interface Request {
      traceId?: string;
      requestId?: string;
    }
  }
}
/* eslint-enable @typescript-eslint/no-namespace */

/**
 * Default headers checked when extracting an incoming trace ID, in priority order:
 *   1. traceparent  — W3C Trace Context (OpenTelemetry standard)
 *   2. x-trace-id   — common custom header
 *   3. x-request-id — used by AWS ALB, NGINX, etc.
 *   4. x-correlation-id — used by Azure / enterprise ESBs
 *   5. trace-id     — legacy shorthand
 *
 * NOTE: for `traceparent` the format is `00-<traceId>-<spanId>-<flags>`.
 * We store the full header value as-is so downstream systems can forward it
 * unmodified. If you need only the 32-char traceId segment, configure a
 * custom extractor via TraceIdConfig.extractor.
 */
const DEFAULT_TRACE_HEADERS = [
  'traceparent',
  'x-trace-id',
  'x-request-id',
  'x-correlation-id',
  'trace-id',
];

@Injectable()
export class TraceMiddleware implements NestMiddleware {
  constructor(@Optional() private readonly config?: TraceIdConfig) {
    const defaultExtractor = {
      header: DEFAULT_TRACE_HEADERS,
      query: ['traceId', 'trace_id'],
    };
    this.config = {
      enabled: true,
      generator: generateTraceId,
      contextKey: 'traceId',
      ...config,
      extractor: config?.extractor
        ? { ...defaultExtractor, ...config.extractor }
        : defaultExtractor,
    };
  }

  use(req: Request, res: Response, next: NextFunction): void {
    if (!this.config?.enabled) {
      return next();
    }

    let traceId: string | undefined;

    // Try to extract existing trace ID
    if (this.config.extractor) {
      traceId = extractTraceId(req, this.config.extractor);
    }

    // Generate new trace ID if not found
    if (!traceId) {
      traceId = this.config.generator ? this.config.generator() : generateTraceId();
    }

    // Set trace ID in request
    req.traceId = traceId;
    req.requestId = req.requestId || generateTraceId();

    // Set response headers
    res.setHeader('X-Trace-Id', traceId);
    res.setHeader('X-Request-Id', req.requestId);

    // Run with trace context
    runWithTraceId(
      traceId,
      () => {
        next();
      },
      {
        requestId: req.requestId,
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
      }
    );
  }
}

/**
 * Factory function to create trace middleware with configuration
 */
export function createTraceMiddleware(config?: TraceIdConfig): TraceMiddleware {
  return new TraceMiddleware(config);
}

/**
 * Functional middleware for Express-style usage
 */
export function traceMiddleware(config?: TraceIdConfig) {
  const defaultExtractor = {
    header: DEFAULT_TRACE_HEADERS,
    query: ['traceId', 'trace_id'],
  };
  const traceConfig = {
    enabled: true,
    generator: generateTraceId,
    contextKey: 'traceId',
    ...config,
    extractor: config?.extractor ? { ...defaultExtractor, ...config.extractor } : defaultExtractor,
  };

  return (req: Request, res: Response, next: NextFunction) => {
    if (!traceConfig.enabled) {
      return next();
    }

    let traceId: string | undefined;

    // Try to extract existing trace ID
    if (traceConfig.extractor) {
      traceId = extractTraceId(req, traceConfig.extractor);
    }

    // Generate new trace ID if not found
    if (!traceId) {
      traceId = traceConfig.generator ? traceConfig.generator() : generateTraceId();
    }

    // Set trace ID in request
    req.traceId = traceId;
    req.requestId = req.requestId || generateTraceId();

    // Set response headers
    res.setHeader('X-Trace-Id', traceId);
    res.setHeader('X-Request-Id', req.requestId);

    // Run with trace context
    runWithTraceId(
      traceId,
      () => {
        next();
      },
      {
        requestId: req.requestId,
        method: req.method,
        url: req.url,
        userAgent: req.get('User-Agent'),
        ip: req.ip || req.connection.remoteAddress,
      }
    );
  };
}
