/**
 * LogixiaLoggerModule trace config provider token
 *
 * The 'TRACE_CONFIG' provider token is exported as LOGIXIA_TRACE_CONFIG so the
 * trace interceptor factories inject it through one shared constant.
 */

import { LOGIXIA_TRACE_CONFIG, LogixiaLoggerModule } from '../logitron-logger.module';

describe('LogixiaLoggerModule trace config token', () => {
  it('registers the resolved trace config under LOGIXIA_TRACE_CONFIG', () => {
    const traceId = { enabled: true, contextKey: 'x-trace' };

    const dynamicModule = LogixiaLoggerModule.forRoot({ traceId });
    const traceProvider = dynamicModule.providers.find(
      (provider) => (provider as { provide?: unknown }).provide === LOGIXIA_TRACE_CONFIG
    ) as { useValue: unknown } | undefined;

    expect(LOGIXIA_TRACE_CONFIG).toBe('TRACE_CONFIG');
    expect(traceProvider?.useValue).toEqual(traceId);
  });
});
