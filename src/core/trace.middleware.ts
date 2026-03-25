/**
 * Trace ID middleware for NestJS integration
 */

import type { NestMiddleware } from '@nestjs/common';
import { Injectable, Optional } from '@nestjs/common';
import type { NextFunction, Request, Response } from 'express';

import type { TraceIdConfig } from '../types';
import { DEFAULT_TRACE_HEADERS, extractTraceId, TraceContext } from '../utils/trace.utils';

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
    // Register the user's contextKey so getCurrentTraceId() / getTraceContextKey() reflect it
    this.ctx.setContextKey(this.config.contextKey ?? 'traceId');
  }

  use(req: Request, res: Response, next: NextFunction): void {
    if (!this.config?.enabled) {
      return next();
    }

    let traceId: string | undefined;

    if (this.config.extractor) {
      traceId = extractTraceId(req, this.config.extractor);
    }

    if (!traceId) {
      traceId = this.config.generator ? this.config.generator() : this.ctx.generate();
    }

    req.traceId = traceId;

    res.setHeader('X-Trace-Id', traceId);

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
  ctx.setContextKey(traceConfig.contextKey ?? 'traceId');

  return (req: Request, res: Response, next: NextFunction) => {
    if (!traceConfig.enabled) {
      return next();
    }

    let traceId: string | undefined;

    if (traceConfig.extractor) {
      traceId = extractTraceId(req, traceConfig.extractor);
    }

    if (!traceId) {
      traceId = traceConfig.generator ? traceConfig.generator() : ctx.generate();
    }

    req.traceId = traceId;

    res.setHeader('X-Trace-Id', traceId);

    ctx.run(traceId, () => next(), {
      method: req.method,
      url: req.url,
      userAgent: req.get('User-Agent'),
      ip: req.ip || req.connection.remoteAddress,
    });
  };
}
