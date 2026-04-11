/**
 * TraceIdGuard
 *
 * Verifies that a traceId is already present in AsyncLocalStorage.
 * TraceMiddleware (wired in LogixiaLoggerModule) handles all extraction
 * (headers → query → body → params) + ALS injection before guards run.
 *
 * This guard's only job: if ALS has no traceId → throw ForbiddenException
 * with a message that tells the caller exactly which sources are configured
 * in app.module.ts (dynamic — no hardcoded keys).
 *
 * Usage:
 *   @UseGuards(TraceIdGuard)
 */

import type { CanActivate, ExecutionContext } from '@nestjs/common';
import { ForbiddenException, Inject, Injectable, Optional } from '@nestjs/common';

import { LOGIXIA_LOGGER_CONFIG } from '../../../../src/core/logitron-logger.module';
import type { LoggerConfig, TraceIdExtractorConfig } from '../../../../src/types';
import { getCurrentTraceId } from '../../../../src/utils/trace.utils';

@Injectable()
export class TraceIdGuard implements CanActivate {
  private readonly missingMsg: string;

  constructor(
    @Optional() @Inject(LOGIXIA_LOGGER_CONFIG) config: Partial<LoggerConfig> | undefined,
  ) {
    const extractor = typeof config?.traceId === 'object' ? config.traceId.extractor : undefined;
    this.missingMsg = buildMissingMessage(extractor);
  }

  canActivate(_ctx: ExecutionContext): boolean {
    if (!getCurrentTraceId()) {
      throw new ForbiddenException(this.missingMsg);
    }
    return true;
  }
}

const arr = (v: string | string[]): string[] => (Array.isArray(v) ? v : [v]);

/**
 * Builds a human-readable error message from the configured extractor so the
 * caller knows exactly which headers / query params / body fields / params to send.
 *
 * Example output:
 *   "Missing traceId — supply it via:
 *     header : x-trace-id | x-request-id
 *     query  : ?traceId=
 *     body   : { traceId }
 *     param  : /:traceId"
 */
function buildMissingMessage(extractor: TraceIdExtractorConfig | undefined): string {
  if (!extractor) {
    return 'Missing traceId — no extractor configured in LogixiaLoggerModule.';
  }

  const lines: string[] = [];

  if (extractor.header) {
    lines.push(`  header : ${arr(extractor.header).join(' | ')}`);
  }
  if (extractor.query) {
    lines.push(`  query  : ?${arr(extractor.query).join('= | ?')}=`);
  }
  if (extractor.body) {
    lines.push(`  body   : { ${arr(extractor.body).join(' | ')} }`);
  }
  if (extractor.params) {
    lines.push(`  param  : /:${arr(extractor.params).join(' | /:')}`);
  }

  return lines.length
    ? `Missing traceId — supply it via:\n${lines.join('\n')}`
    : 'Missing traceId — extractor configured but no keys defined.';
}
