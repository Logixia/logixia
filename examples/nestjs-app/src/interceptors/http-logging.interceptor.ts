import { Injectable, type NestInterceptor, type ExecutionContext, type CallHandler } from '@nestjs/common';
import { Observable } from 'rxjs';
import { tap, catchError } from 'rxjs/operators';
import { throwError } from 'rxjs';
import type { Request, Response } from 'express';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';

/**
 * Global HTTP logging interceptor.
 *
 * Logs every incoming request + outgoing response with:
 *   - method, url, statusCode, durationMs
 *   - traceId (from AsyncLocalStorage, set by TraceMiddleware)
 *
 * Format: timestamp level [thread-gate] [traceId] [HttpLoggingInterceptor] message { ... }
 */
@Injectable()
export class HttpLoggingInterceptor implements NestInterceptor {
  private readonly log: LogixiaLoggerService;

  constructor(private readonly logger: LogixiaLoggerService) {
    this.log = this.logger.child('HttpLoggingInterceptor');
  }

  intercept(context: ExecutionContext, next: CallHandler): Observable<unknown> {
    const req = context.switchToHttp().getRequest<Request>();
    const res = context.switchToHttp().getResponse<Response>();
    const { method, url } = req;
    const start = Date.now();

    // Log incoming request
    this.log.info(`→ ${method} ${url}`, {
      method,
      url,
      userAgent: req.headers['user-agent'],
      ip: req.ip,
    });

    return next.handle().pipe(
      tap(() => {
        const ms = Date.now() - start;
        this.log.info(`← ${method} ${url} ${res.statusCode}`, {
          method,
          url,
          statusCode: res.statusCode,
          durationMs: ms,
        });
      }),
      catchError((err: unknown) => {
        // Error path — ExceptionFilter will also log, but we note timing here
        const ms = Date.now() - start;
        this.log.debug(`✗ ${method} ${url} error after ${ms}ms`, {
          method,
          url,
          durationMs: ms,
          errorName: err instanceof Error ? err.name : 'Unknown',
        });
        return throwError(() => err);
      }),
    );
  }
}
