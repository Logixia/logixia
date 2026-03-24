/**
 * NestJS Integration Example — Logixia Logger
 *
 * Demonstrates:
 *  1. LogixiaLoggerService with correct LoggerConfig shape
 *  2. Custom level proxy methods  → service.kafka() / service.payment()
 *  3. Auto-palette colors         → unlisted levels get a visible color automatically
 *  4. LogixiaLoggerModule.forRoot() wiring (shown as comments — requires NestJS runtime)
 *  5. child() loggers, context, setLevel, logLevel() escape hatch
 *  6. TraceId — automatic per-request correlation ID in every log line
 *
 * Run:
 *   npx ts-node examples/nestjs-example.ts
 */

import { LogixiaLoggerService } from '../src/core/logitron-nestjs.service';
import { LogixiaContext } from '../src/context/async-context';
import { LogLevel } from '../src/types';

// ─────────────────────────────────────────────────────────────────────────────
// 1.  How you wire it up in a real NestJS app
// ─────────────────────────────────────────────────────────────────────────────
//
// app.module.ts
// ─────────────
// @Module({
//   imports: [
//     LogixiaLoggerModule.forRoot({
//       appName:     'thread-gate',
//       environment: 'production',
//       traceId:     true,
//       format:      { timestamp: true, colorize: true, json: false },
//       levelOptions: {
//         level: 'info',
//         levels: {
//           error: 0, warn: 1, info: 2, debug: 3, verbose: 4,
//           kafka:   2,   // same priority as info
//           mysql:   2,
//           payment: 1,   // same priority as warn — always surface these
//         },
//         colors: {
//           error: 'red', warn: 'yellow', info: 'blue', debug: 'green', verbose: 'cyan',
//           kafka: 'magenta', mysql: 'cyan', payment: 'brightYellow',
//         },
//       },
//     }),
//   ],
// })
// export class AppModule {}
//
// main.ts
// ───────
// const logger = app.get(LogixiaLoggerService);
// app.useLogger(logger);           ← replaces NestJS built-in console logger
//
// any.service.ts
// ──────────────
// constructor(private readonly logger: LogixiaLoggerService) {}
//
// (this.logger).kafka('Producer connected');          // proxy method
// (this.logger).payment('Charge captured', { txnId });
// this.logger.logLevel('kafka', 'msg', data);                // typed escape-hatch

// ─────────────────────────────────────────────────────────────────────────────
// 2.  Standalone runnable demo
// ─────────────────────────────────────────────────────────────────────────────

async function run() {
  console.log('\n════════════════════════════════════════');
  console.log(' Logixia — NestJS Service Demo');
  console.log('════════════════════════════════════════\n');

  // ── 2a. Standard NestJS log levels ───────────────────────────────────────
  console.log('── Standard levels ─────────────────────\n');

  const basic = LogixiaLoggerService.create({
    appName: 'DemoApp',
    environment: 'development',
    traceId: false,
    format: { timestamp: true, colorize: true, json: false },
    levelOptions: {
      level: LogLevel.DEBUG,
      levels: {
        [LogLevel.ERROR]:   0,
        [LogLevel.WARN]:    1,
        [LogLevel.INFO]:    2,
        [LogLevel.DEBUG]:   3,
        [LogLevel.VERBOSE]: 4,
      },
      colors: {
        [LogLevel.ERROR]:   'red',
        [LogLevel.WARN]:    'yellow',
        [LogLevel.INFO]:    'blue',
        [LogLevel.DEBUG]:   'green',
        [LogLevel.VERBOSE]: 'cyan',
      },
    },
  });

  // NestJS compat overloads (void, string context) — used by NestJS framework internals
  basic.log('Application bootstrapped', 'Bootstrap');
  basic.warn('Config missing, falling back to defaults', 'ConfigService');
  basic.error('Redis connection refused', new Error('ECONNREFUSED').stack, 'CacheModule');

  // Native async overloads (Promise<void>, structured data) — use in your own code
  await basic.info('HTTP server listening', { port: 3000, env: 'development' });
  await basic.debug('Route registered', { method: 'GET', path: '/api/users' });

  // ── 2b. Custom level proxy methods ───────────────────────────────────────
  console.log('\n── Custom level proxy methods ──────────\n');

  /**
   * Every key you add to `levelOptions.levels` becomes a method on the service.
   *
   *   service.kafka(msg, data)    → logLevel('kafka',   msg, data)
   *   service.mysql(msg, data)    → logLevel('mysql',   msg, data)
   *   service.payment(msg, data)  → logLevel('payment', msg, data)
   *
   * This is the fix for "this.logger.payment() doesn't work" — no casting needed
   * on your side; Logixia registers these automatically at construction time.
   */
  const appLogger = LogixiaLoggerService.create({
    appName: 'thread-gate',
    environment: 'development',
    traceId: true,
    format: { timestamp: true, colorize: true, json: false },
    levelOptions: {
      level: 'verbose',
      levels: {
        [LogLevel.ERROR]:   0,
        [LogLevel.WARN]:    1,
        [LogLevel.INFO]:    2,
        [LogLevel.DEBUG]:   3,
        [LogLevel.VERBOSE]: 4,
        // ── domain-specific levels ────────────────────────────────────────
        kafka:   2,   // surfaces at INFO threshold
        mysql:   2,
        payment: 1,   // surfaces at WARN threshold — treat as high priority
      },
      colors: {
        [LogLevel.ERROR]:   'red',
        [LogLevel.WARN]:    'yellow',
        [LogLevel.INFO]:    'blue',
        [LogLevel.DEBUG]:   'green',
        [LogLevel.VERBOSE]: 'cyan',
        // IntelliSense now suggests 'kafka' | 'mysql' | 'payment' as valid keys here
        kafka:   'magenta',
        mysql:   'cyan',
        payment: 'brightYellow',
      },
    },
  });

  appLogger.kafka('Kafka producer connected', {
    broker:   'localhost:9092',
    clientId: 'thread-gate',
    topic:    'user.events',
  });

  appLogger.mysql('Query executed', {
    query:    'SELECT * FROM users WHERE active = true',
    duration: '14ms',
    rows:     42,
  });

  appLogger.payment('Charge succeeded', {
    txnId:    'txn_3Pv9Xk',
    amount:   99.99,
    currency: 'USD',
    userId:   'usr_abc123',
  });

  // logLevel() — typed escape-hatch, works with any level string
  await appLogger.logLevel('kafka', 'Consumer group rebalanced', {
    groupId:    'thread-gate-group',
    partitions: [0, 1, 2],
  });

  // ── 2c. Auto-palette — no colors defined ─────────────────────────────────
  console.log('\n── Auto-palette (colors omitted) ───────\n');

  /**
   * If you don't set a color for a custom level, Logixia picks one from the
   * palette:  magenta → cyan → yellow → green → blue  (cycling).
   *
   * This is the fix for "KAFKA / MYSQL appear uncolored":
   * before this fix they silently fell back to 'white' (invisible on dark terminals).
   */
  const autoLogger = LogixiaLoggerService.create({
    appName: 'NotifService',
    traceId: false,
    format:  { timestamp: false, colorize: true, json: false },
    levelOptions: {
      level: 'webhook',
      levels: {
        [LogLevel.ERROR]: 0,
        [LogLevel.WARN]:  1,
        [LogLevel.INFO]:  2,
        sms:     3,   // auto → magenta
        push:    4,   // auto → cyan
        webhook: 5,   // auto → yellow
      },
      colors: {
        [LogLevel.ERROR]: 'red',
        [LogLevel.WARN]:  'yellow',
        [LogLevel.INFO]:  'blue',
        // sms / push / webhook intentionally omitted → auto-palette kicks in
      },
    },
  });

  await (autoLogger).sms('OTP dispatched', { phone: '+91-XXXXXX9999' });
  await (autoLogger).push('Push notification delivered', { deviceId: 'dev_abc' });
  await (autoLogger).webhook('Webhook fired', { url: 'https://hooks.example.com/pay', status: 200 });

  // ── 2d. Child loggers ─────────────────────────────────────────────────────
  console.log('\n── Child loggers ───────────────────────\n');

  appLogger.setContext('PaymentService');
  await appLogger.info('Processing payment request');

  // child() returns a new service scoped to "OrderService"
  const orderLogger = appLogger.child('OrderService', { region: 'ap-south-1' });
  await orderLogger.info('Order created', { orderId: 'ord_789' });

  // child() returns the base service type — use logLevel() for custom levels on children
  await orderLogger.logLevel('payment', 'Order charge captured', {
    orderId: 'ord_789',
    amount:  49.99,
  });

  // ── 2e. Timing helpers ────────────────────────────────────────────────────
  console.log('\n── Timing ──────────────────────────────\n');

  appLogger.time('db:findAll');
  await new Promise<void>((r) => setTimeout(r, 60));
  await appLogger.timeEnd('db:findAll');

  const users = await appLogger.timeAsync('api:fetchProfiles', async () => {
    await new Promise<void>((r) => setTimeout(r, 30));
    return [{ id: 'u_1', name: 'Sanjeev' }, { id: 'u_2', name: 'Priya' }];
  });
  await appLogger.info('Profiles loaded', { count: users.length });

  // ── 2f. Level management ─────────────────────────────────────────────────
  console.log('\n── Level management ────────────────────\n');

  appLogger.debug('Visible at current threshold (verbose)');
  appLogger.setLevel(LogLevel.WARN);
  appLogger.debug('Suppressed — debug(3) < warn(1)');
  appLogger.warn('Visible at WARN threshold');
  appLogger.setLevel('verbose'); // restore

  // ── 2g. TraceId — correlation ID propagated into every log line ──────────
  console.log('\n── TraceId ─────────────────────────────\n');

  /**
   * With `traceId: true` (or a TraceIdConfig object) every log entry carries
   * a stable correlation ID so you can grep all lines for a single request.
   *
   * Two ways to use it:
   *
   * 1. LogixiaContext.run(traceId, fn)
   *    All logs inside `fn` automatically carry `traceId` — the preferred way
   *    inside a NestJS request lifecycle (TraceMiddleware does this for you).
   *
   * 2. logger.getCurrentTraceId()
   *    Read the active trace ID from AsyncLocalStorage at any point.
   */
  await LogixiaContext.run({ traceId: 'req_demo_abc123' }, async () => {
    // Every log inside this callback carries traceId: 'req_demo_abc123'
    await appLogger.info('Request received', { method: 'POST', path: '/api/orders' });
    await appLogger.kafka('Message published', { topic: 'order.created', key: 'ord_789' });
    await appLogger.payment('Charge initiated', { amount: 49.99, currency: 'USD' });

    const traceId = appLogger.getCurrentTraceId();
    console.log('  Active traceId:', traceId); // req_demo_abc123
  });

  // Outside the context — logger falls back to its own stable per-instance ID
  await appLogger.info('After context — own fallback traceId active');

  // ── 2h. Error logging ─────────────────────────────────────────────────────
  console.log('\n── Error logging ───────────────────────\n');

  try {
    throw new Error('DB connection timed out after 5000ms');
  } catch (err) {
    await appLogger.error(err as Error, { service: 'UserRepository', retries: 3 });
  }

  await appLogger.close();
  await autoLogger.close();
  await basic.close();

  console.log('\n════════════════════════════════════════');
  console.log(' Demo complete');
  console.log('════════════════════════════════════════\n');
}

run().catch(console.error);
