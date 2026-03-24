/**
 * Custom Levels Example — Logixia Logger
 *
 * Demonstrates:
 *  1. Defining domain-specific log levels (analytics, payment, kafka, etc.)
 *  2. Explicit colors per level — IntelliSense now narrows keys to your level names
 *  3. Auto-palette — levels with no explicit color get a visible color automatically
 *     (magenta → cyan → yellow → green → blue, cycling)
 *  4. Proxy methods on LogixiaLoggerService — service.payment() just works
 *
 * Run:
 *   npx ts-node examples/custom-levels.ts
 */

import { createLogger, LogixiaLogger } from '../src/core/logitron-logger';
import { LogixiaLoggerService }         from '../src/core/logitron-nestjs.service';
import { LogLevel }                     from '../src/types';

// ─────────────────────────────────────────────────────────────────────────────
// 1.  E-commerce logger — explicit colors for every level
// ─────────────────────────────────────────────────────────────────────────────

const ecommerceLogger = createLogger({
  appName: 'EcommerceApp',
  format:  { timestamp: false, colorize: true, json: false },
  traceId: false,
  levelOptions: {
    level: 'marketing', // show everything down to marketing
    levels: {
      [LogLevel.ERROR]: 0,
      [LogLevel.WARN]:  1,
      [LogLevel.INFO]:  2,
      [LogLevel.DEBUG]: 3,
      order:     2,   // order processing — same priority as info
      payment:   1,   // payment — same priority as warn (always visible)
      inventory: 2,
      customer:  3,
      marketing: 4,
    },
    colors: {
      // IntelliSense now suggests all of your level names as valid keys,
      // plus the built-in levels (error | warn | info | debug | trace | verbose).
      [LogLevel.ERROR]: 'red',
      [LogLevel.WARN]:  'yellow',
      [LogLevel.INFO]:  'blue',
      [LogLevel.DEBUG]: 'green',
      order:     'brightBlue',
      payment:   'brightYellow',
      inventory: 'cyan',
      customer:  'brightGreen',
      marketing: 'brightCyan',
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 2.  Infrastructure logger — auto-palette for unlisted levels
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Don't want to pick colors manually? Just omit them.
 * Logixia assigns a distinctive color from the palette for each unlisted level:
 *   first unlisted  → magenta
 *   second unlisted → cyan
 *   third unlisted  → yellow
 *   ... and so on, cycling through ['magenta','cyan','yellow','green','blue']
 *
 * This is the fix for "KAFKA / MYSQL appear uncolored" — they used to silently
 * fall back to white which is invisible on dark terminals.
 */
const infraLogger = createLogger({
  appName: 'InfraApp',
  format:  { timestamp: false, colorize: true, json: false },
  traceId: false,
  levelOptions: {
    level: 'maintenance',
    levels: {
      [LogLevel.ERROR]: 0,
      [LogLevel.WARN]:  1,
      [LogLevel.INFO]:  2,
      [LogLevel.DEBUG]: 3,
      kafka:       2,   // auto → magenta
      mysql:       2,   // auto → cyan
      deployment:  1,   // auto → yellow
      monitoring:  2,   // auto → green
      maintenance: 4,   // auto → blue
    },
    colors: {
      [LogLevel.ERROR]: 'red',
      [LogLevel.WARN]:  'yellow',
      [LogLevel.INFO]:  'blue',
      [LogLevel.DEBUG]: 'green',
      // kafka / mysql / deployment / monitoring / maintenance → auto-palette
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 3.  NestJS service — proxy methods for custom levels
// ─────────────────────────────────────────────────────────────────────────────

/**
 * LogixiaLoggerService creates a proxy method for every key in levelOptions.levels
 * that doesn't already have a built-in implementation.
 *
 *   service.kafka(msg, data)    // ← just works, no casting
 *   service.payment(msg, data)  // ← just works
 *
 * Under the hood each proxy calls: this.logger.logLevel(levelName, msg, data)
 */
const nestService = LogixiaLoggerService.create({
  appName: 'NestApp',
  traceId: false,
  format:  { timestamp: false, colorize: true, json: false },
  levelOptions: {
    level: 'payment',
    levels: {
      [LogLevel.ERROR]: 0,
      [LogLevel.WARN]:  1,
      [LogLevel.INFO]:  2,
      [LogLevel.DEBUG]: 3,
      kafka:   2,
      payment: 1,
    },
    colors: {
      [LogLevel.ERROR]: 'red',
      [LogLevel.WARN]:  'yellow',
      [LogLevel.INFO]:  'blue',
      [LogLevel.DEBUG]: 'green',
      kafka:   'magenta',
      payment: 'brightYellow',
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 4.  Run all demos
// ─────────────────────────────────────────────────────────────────────────────

async function runDemo() {
  console.log('\n════════════════════════════════════════');
  console.log(' Custom Levels Demo');
  console.log('════════════════════════════════════════\n');

  // ── E-commerce ─────────────────────────────────────────────────────────────
  console.log('── E-commerce logger (explicit colors) ─\n');

  await ecommerceLogger.error('Payment gateway unreachable');
  await ecommerceLogger.payment('Charge captured', { txnId: 'txn_abc', amount: 99.99 });
  await ecommerceLogger.order('Order confirmed', { orderId: 'ord_001', items: 3 });
  await ecommerceLogger.inventory('Stock updated', { sku: 'SKU-9001', qty: 500 });
  await ecommerceLogger.customer('Profile viewed', { userId: 'usr_42' });
  await ecommerceLogger.marketing('Campaign clicked', { campaign: 'summer-sale' });

  // ── Infrastructure (auto-palette) ──────────────────────────────────────────
  console.log('\n── Infra logger (auto-palette colors) ──\n');

  await infraLogger.kafka('Producer connected', { broker: 'localhost:9092' });
  await infraLogger.mysql('Query executed', { query: 'SELECT 1', ms: 2 });
  await infraLogger.deployment('Release v2.1.0 complete', { pods: 3 });
  await infraLogger.monitoring('Health check passed', { latency: '12ms' });
  await infraLogger.maintenance('Nightly vacuum scheduled');

  // ── NestJS service proxy methods ───────────────────────────────────────────
  console.log('\n── NestJS service proxy methods ─────────\n');

  await nestService.kafka('Consumer group rebalanced', {
    groupId:    'app-group',
    partitions: [0, 1, 2],
  });
  await nestService.payment('Subscription renewed', {
    userId:    'usr_99',
    plan:      'pro',
    amount:    29.99,
    currency:  'USD',
  });

  // logLevel() — typed escape hatch, equivalent to the proxy
  await nestService.logLevel('kafka', 'Offset committed', { offset: 1024 });

  // ── Dynamic level change ───────────────────────────────────────────────────
  console.log('\n── Dynamic level change ─────────────────\n');

  console.log('Level before:', ecommerceLogger.getLevel());
  ecommerceLogger.setLevel(LogLevel.WARN);
  await ecommerceLogger.order('Suppressed — order(2) > warn(1)');
  await ecommerceLogger.warn('Still visible at warn');
  ecommerceLogger.setLevel('marketing'); // restore

  console.log('\n════════════════════════════════════════');
  console.log(' Demo complete');
  console.log('════════════════════════════════════════\n');
}

runDemo().catch(console.error);

export { ecommerceLogger, infraLogger, nestService };
