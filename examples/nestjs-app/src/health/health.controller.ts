import { Controller, Get, Post } from '@nestjs/common';
import { LogixiaLoggerService } from '../../../../src/core/logitron-nestjs.service';
import { RequestContextManager } from '../../../../src/core/request-context';
import { getCurrentTraceId } from '../../../../src/utils/trace.utils';
import { EventsGateway } from '../events/events.gateway';

/**
 * Health / diagnostics controller.
 *
 * GET  /health          — liveness check with current traceId
 * GET  /health/context  — RequestContextManager stats
 * POST /health/broadcast — trigger server-push WS event (shows HTTP→WS traceId propagation)
 * GET  /health/log-levels — demonstrate all log levels from a single request
 */
@Controller('health')
export class HealthController {
  private readonly log: LogixiaLoggerService;

  constructor(
    private readonly logger: LogixiaLoggerService,
    private readonly eventsGateway: EventsGateway,
  ) {
    this.log = this.logger.child('HealthController');
  }

  @Get()
  async check() {
    const traceId = getCurrentTraceId();
    await this.log.info('Health check', { traceId });
    return { status: 'ok', traceId, ts: new Date().toISOString() };
  }

  @Get('context')
  async contextStats() {
    const stats = RequestContextManager.getStats();
    await this.log.info('RequestContext stats', stats);
    return stats;
  }

  /**
   * Fires a server-push WS event.
   * Because this HTTP handler runs inside the TraceMiddleware context,
   * the traceId from this HTTP request is propagated into the WS broadcast log.
   */
  @Post('broadcast')
  async broadcast() {
    const traceId = getCurrentTraceId();
    await this.log.info('Triggering WS broadcast from HTTP', { traceId });
    this.eventsGateway.broadcastToAll('server:push', { msg: 'hello from HTTP' }, traceId);
    return { ok: true, traceId };
  }

  /**
   * Fires all log levels so you can see exact console output.
   */
  @Get('log-levels')
  async allLevels() {
    const traceId = getCurrentTraceId();
    const log = this.log.child('LogLevelDemo', { traceId });

    await log.info('This is INFO');
    await log.debug('This is DEBUG');
    await log.warn('This is WARN');
    await log.verbose('This is VERBOSE');
    try { throw new Error('demo error'); } catch (e) {
      await log.error(e as Error, { source: 'log-levels route' });
    }

    return { ok: true, traceId, levels: ['info', 'debug', 'warn', 'verbose', 'error'] };
  }
}
