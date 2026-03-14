/**
 * logixia/testing — Test utilities for logixia.
 *
 * @example
 * ```ts
 * import { createMockLogger } from 'logixia/testing';
 *
 * const mock = createMockLogger();
 * await myService.processOrder('123', mock.logger);
 *
 * mock.expectLog('info', 'order processed');
 * mock.expectLog('info', { orderId: '123' });
 * mock.reset();
 * ```
 */

export type { LogMatcher, MockLogCall, MockLoggerInstance } from './testing/mock-logger';
export { createMockLogger } from './testing/mock-logger';
