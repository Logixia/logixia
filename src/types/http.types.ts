/**
 * HTTP-related type definitions for Logitron
 */

export interface HttpRequest {
  method: string;
  url: string;
  headers: Record<string, string | string[]>;
  query?: Record<string, any>;
  params?: Record<string, any>;
  body?: any;
  ip?: string;
  userAgent?: string;
  timestamp: number;
}

export interface HttpResponse {
  statusCode: number;
  headers: Record<string, string | string[]>;
  body?: any;
  timestamp: number;
  contentLength?: number;
}

export interface HttpError extends Error {
  statusCode?: number;
  code?: string;
  details?: Record<string, any>;
}

export interface RequestTiming {
  start: number;
  end?: number;
  duration?: number;
  phases?: {
    dns?: number;
    tcp?: number;
    tls?: number;
    request?: number;
    response?: number;
  };
}

export interface RequestMetrics {
  requestId: string;
  method: string;
  url: string;
  statusCode?: number;
  duration?: number;
  contentLength?: number;
  userAgent?: string;
  ip?: string;
  timestamp: number;
}
