/**
 * Trace ID middleware for NestJS integration
 */

import type { NestMiddleware } from '@nestjs/common';
import { Injectable, Optional } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

import type { TraceIdConfig } from '../types';
import { DEFAULT_TRACE_HEADERS, extractTraceId, TraceContext } from '../utils/trace.utils';

/** Default response header used to echo the resolved traceId back to the caller. */
export const DEFAULT_TRACE_RESPONSE_HEADER = 'X-Trace-Id';

/**
 * Resolve the response header name from config.
 * - `undefined`   → default `'X-Trace-Id'`
 * - `string`      → user's custom header
 * - `false`       → `null` (suppress entirely)
 */
export function resolveResponseHeader(config?: TraceIdConfig): string | null {
  if (config?.responseHeader === false) return null;
  return config?.responseHeader ?? DEFAULT_TRACE_RESPONSE_HEADER;
}

// Extend Express Request interface — requires namespace to augment Express typings
/* eslint-disable @typescript-eslint/no-namespace */
declare global {
  namespace Express {
    interface Request {
      traceId?: string;
    }
  }
}
/* eslint-enable @typescript-eslint/no-namespace */

@Injectable()
export class TraceMiddleware implements NestMiddleware {
  private readonly ctx = TraceContext.instance;

  constructor(@Optional() private readonly config?: TraceIdConfig) {
    const defaultExtractor = {
      header: DEFAULT_TRACE_HEADERS,
      query: ['traceId', 'trace_id'],
    };
    this.config = {
      enabled: true,
      generator: () => this.ctx.generate(),
      contextKey: 'traceId',
      ...config,
      extractor: config?.extractor
        ? { ...defaultExtractor, ...config.extractor }
        : defaultExtractor,
    };
    // Only mutate the process-wide context key when tracing is actually enabled —
    // otherwise a disabled middleware would still change global state.
    if (this.config.enabled) {
      this.ctx.setContextKey(this.config.contextKey ?? 'traceId');
    }
  }

  use(req: Request, res: Response, next: NextFunction): void {
    if (!this.config?.enabled) {
      return next();
    }

    let traceId: string | undefined;

    if (this.config.extractor) {
      traceId = extractTraceId(req, this.config.extractor);
    }

    if (!traceId && this.config.generator) {
      const candidate = this.config.generator();
      // Guard against a user-supplied generator that returns a bad value —
      // fall back to the built-in UUID generator so the request always has
      // a valid, non-empty traceId downstream.
      if (typeof candidate === 'string' && candidate.trim().length > 0) {
        traceId = candidate;
      } else {
        process.stderr.write(
          '[logixia] TraceIdConfig.generator returned a non-string/empty value — using built-in generator.\n'
        );
      }
    }
    if (!traceId) {
      traceId = this.ctx.generate();
    }

    req.traceId = traceId;

    const header = resolveResponseHeader(this.config);
    if (header) res.setHeader(header, traceId);

    this.ctx.run(traceId, () => next(), {
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection.remoteAddress,
    });
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
  const ctx = TraceContext.instance;
  const defaultExtractor = {
    header: DEFAULT_TRACE_HEADERS,
    query: ['traceId', 'trace_id'],
  };
  const traceConfig = {
    enabled: true,
    generator: () => ctx.generate(),
    contextKey: 'traceId',
    ...config,
    extractor: config?.extractor ? { ...defaultExtractor, ...config.extractor } : defaultExtractor,
  };

  // Only mutate the process-wide context key when the middleware is actually
  // enabled — otherwise a disabled instance would still change global state.
  if (traceConfig.enabled) {
    ctx.setContextKey(traceConfig.contextKey ?? 'traceId');
  }

  return (req: Request, res: Response, next: NextFunction) => {
    if (!traceConfig.enabled) {
      return next();
    }

    let traceId: string | undefined;

    if (traceConfig.extractor) {
      traceId = extractTraceId(req, traceConfig.extractor);
    }

    if (!traceId && traceConfig.generator) {
      const candidate = traceConfig.generator();
      if (typeof candidate === 'string' && candidate.trim().length > 0) {
        traceId = candidate;
      } else {
        process.stderr.write(
          '[logixia] TraceIdConfig.generator returned a non-string/empty value — using built-in generator.\n'
        );
      }
    }
    if (!traceId) {
      traceId = ctx.generate();
    }

    req.traceId = traceId;

    const header = resolveResponseHeader(traceConfig);
    if (header) res.setHeader(header, traceId);

    ctx.run(traceId, () => next(), {
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection.remoteAddress,
    });
  };
}
