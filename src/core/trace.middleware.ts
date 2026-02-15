/**
 * Trace ID middleware for NestJS integration
 */

import { Injectable, NestMiddleware } from "@nestjs/common";
import { Request, Response, NextFunction } from "express";
import {
  generateTraceId,
  extractTraceId,
  runWithTraceId,
  getCurrentTraceId,
} from "../utils/trace.utils";
import type { TraceIdConfig } from "../types";

// Extend Express Request interface
declare global {
  namespace Express {
    interface Request {
      traceId?: string;
      requestId?: string;
    }
  }
}

@Injectable()
export class TraceMiddleware implements NestMiddleware {
  constructor(private readonly config?: TraceIdConfig) {
    this.config = {
      enabled: true,
      generator: generateTraceId,
      contextKey: "traceId",
      extractor: {
        header: ["x-trace-id", "x-request-id", "trace-id"],
        query: ["traceId", "trace_id"],
      },
      ...config,
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
      traceId = this.config.generator
        ? this.config.generator()
        : generateTraceId();
    }

    // Set trace ID in request
    req.traceId = traceId;
    req.requestId = req.requestId || generateTraceId();

    // Set response headers
    res.setHeader("X-Trace-Id", traceId);
    res.setHeader("X-Request-Id", req.requestId);

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
        userAgent: req.get("User-Agent"),
        ip: req.ip || req.connection.remoteAddress,
      },
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
  const traceConfig = {
    enabled: true,
    generator: generateTraceId,
    contextKey: "traceId",
    extractor: {
      header: ["x-trace-id", "x-request-id", "trace-id"],
      query: ["traceId", "trace_id"],
    },
    ...config,
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
      traceId = traceConfig.generator
        ? traceConfig.generator()
        : generateTraceId();
    }

    // Set trace ID in request
    req.traceId = traceId;
    req.requestId = req.requestId || generateTraceId();

    // Set response headers
    res.setHeader("X-Trace-Id", traceId);
    res.setHeader("X-Request-Id", req.requestId);

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
        userAgent: req.get("User-Agent"),
        ip: req.ip || req.connection.remoteAddress,
      },
    );
  };
}
