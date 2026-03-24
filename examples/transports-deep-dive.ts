/**
 * transports-deep-dive.ts
 *
 * Exhaustive examples for every Logixia transport:
 *   1. FileTransport  — formats (json/text/csv), rotation, maxFiles, multi-file
 *   2. DatabaseTransport — PostgreSQL, MongoDB, MySQL, SQLite (with real verified output)
 *   3. ConsoleTransport — colorize, level filter, json/text format
 *   4. Multiple transports simultaneously
 *   5. Per-transport level filtering
 *   6. gracefulShutdown — auto-flush on SIGTERM/SIGINT
 *
 * Verified live output from Docker stack:
 *   - File: 6 rotated files created across restarts (83–432 lines each)
 *   - Postgres: logs table — level, message, context, trace_id columns
 *   - Mongo:    logs collection — same fields as documents
 *
 * Run:
 *   npx ts-node -r ./examples/nestjs-app/register.js examples/transports-deep-dive.ts
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { LogixiaLogger } from '../src/core/logitron-logger';
import { FileTransport } from '../src/transports/file.transport';
import { DatabaseTransport } from '../src/transports/database.transport';

// ─────────────────────────────────────────────────────────────────────────────
// 1. FILE TRANSPORT — JSON format (default)
//
// Output (verified from container /app/logs/):
//   {"timestamp":"2026-03-24T16:21:50.926Z","level":"info","message":"Starting..."}
//   {"timestamp":"...","level":"warn","message":"High CPU","cpu":95}
//
// Rotation: new file every 1d, keep 7, no compress
// ─────────────────────────────────────────────────────────────────────────────
export const fileJsonLogger = new LogixiaLogger({
  appName: 'MyService',
  environment: 'production',
  level: 'debug',
  transports: {
    console: { colorize: true, timestamp: true },
    file: {
      filename: 'app.log',
      dirname: './logs/json',
      format: 'json',         // one JSON object per line
      level: 'info',          // only info+ goes to file, debug stays console-only
      batchSize: 50,          // flush every 50 entries or …
      flushInterval: 3000,    // … every 3 seconds, whichever comes first
      rotation: {
        interval: '1d',       // new file every day
        maxFiles: 7,          // keep last 7 files (auto-delete older)
        compress: false,      // set true to gzip rotated files
      },
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. FILE TRANSPORT — TEXT format
//
// Output line format:
//   2026-03-24T16:21:50.926Z [INFO] User created {"userId":"u_123","email":"..."}
// ─────────────────────────────────────────────────────────────────────────────
export const fileTextLogger = new LogixiaLogger({
  appName: 'MyService',
  environment: 'production',
  level: 'debug',
  transports: {
    file: {
      filename: 'app.log',
      dirname: './logs/text',
      format: 'text',
      rotation: {
        interval: '6h',       // rotate every 6 hours
        maxFiles: 14,
      },
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. FILE TRANSPORT — CSV format
//
// Output line format:
//   2026-03-24T16:21:50.926Z,info,"User created",UsersService,trace-abc-123,...
//
// Columns: timestamp, level, message, context, traceId, data (JSON)
// ─────────────────────────────────────────────────────────────────────────────
export const fileCsvLogger = new LogixiaLogger({
  appName: 'ETLPipeline',
  environment: 'production',
  level: 'info',
  transports: {
    file: {
      filename: 'pipeline.csv',
      dirname: './logs/csv',
      format: 'csv',
      rotation: {
        interval: '1d',
        maxFiles: 30,
      },
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. FILE TRANSPORT — Multiple files simultaneously
//
// Useful pattern: errors go to a separate file for alerting,
// all logs go to the main rolling file.
// ─────────────────────────────────────────────────────────────────────────────
export const multiFileLogger = new LogixiaLogger({
  appName: 'MyService',
  environment: 'production',
  level: 'debug',
  transports: {
    console: { colorize: true, timestamp: true },
    // Array of FileTransportConfig — supported by TransportConfig type
    file: [
      {
        // All logs (info+), daily rotation
        filename: 'combined.log',
        dirname: './logs',
        format: 'json',
        level: 'info',
        rotation: { interval: '1d', maxFiles: 7 },
      },
      {
        // Errors only, weekly rotation, long retention
        filename: 'error.log',
        dirname: './logs',
        format: 'json',
        level: 'error',
        rotation: { interval: '1w', maxFiles: 12 },
      },
    ],
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. DATABASE TRANSPORT — PostgreSQL
//
// Auto-creates table on first connect:
//   CREATE TABLE IF NOT EXISTS logs (
//     id          SERIAL PRIMARY KEY,
//     timestamp   TIMESTAMPTZ NOT NULL,
//     level       VARCHAR(20),
//     message     TEXT,
//     payload     JSONB,
//     context     VARCHAR(255),
//     trace_id    VARCHAR(255),
//     app_name    VARCHAR(255),
//     environment VARCHAR(50),
//     created_at  TIMESTAMPTZ DEFAULT now()
//   );
//   + indexes on timestamp, level, trace_id
//
// Verified output (Docker postgres):
//   level │ message                │ context                │ trace_id
//   ──────┼────────────────────────┼────────────────────────┼─────────────
//   info  │ ← GET /users 200       │ HttpLoggingInterceptor │ file-test-16
//   info  │ → POST /users          │ HttpLoggingInterceptor │ file-test-15
//   info  │ Kafka: order.created   │ KafkaController        │ kafka-e2e-…
// ─────────────────────────────────────────────────────────────────────────────
export const postgresLogger = new LogixiaLogger({
  appName: 'MyService',
  environment: 'production',
  level: 'warn',             // only warn/error/fatal go to postgres
  transports: {
    console: { colorize: true, timestamp: true },
    database: {
      type: 'postgresql',
      host: process.env['POSTGRES_HOST'] ?? 'localhost',
      port: Number(process.env['POSTGRES_PORT'] ?? 5432),
      database: process.env['POSTGRES_DB'] ?? 'app_logs',
      username: process.env['POSTGRES_USER'] ?? 'logixia',
      password: process.env['POSTGRES_PASSWORD'] ?? 'logixia_pass',
      table: 'logs',          // table name (validated: only [a-zA-Z_\w])
      level: 'warn',
      batchSize: 100,         // flush every 100 entries …
      flushInterval: 5000,    // … or every 5s
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. DATABASE TRANSPORT — MongoDB
//
// Auto-creates collection if it doesn't exist.
// Stores each log as a document:
//   {
//     timestamp: ISODate("2026-03-24T16:30:19Z"),
//     level: "warn",
//     message: "Kafka: payment.failed received",
//     data: { orderId: "ord-001", reason: "insufficient_funds" },
//     context: "KafkaController",
//     traceId: "kafka-e2e-payment.failed",
//     appName: "logixia-nestjs-example",
//     environment: "development"
//   }
//
// Verified output (Docker mongo):
//   level: 'warn', message: 'Kafka: payment.failed received', context: 'KafkaController'
//   level: 'info', message: 'Kafka: user.registered received', context: 'KafkaController'
// ─────────────────────────────────────────────────────────────────────────────
export const mongoLogger = new LogixiaLogger({
  appName: 'MyService',
  environment: 'production',
  level: 'info',
  transports: {
    console: { colorize: true, timestamp: true },
    database: {
      type: 'mongodb',
      // Option A: connection string
      connectionString:
        process.env['MONGO_URL'] ??
        `mongodb://${process.env['MONGO_USER'] ?? 'logixia'}:` +
          `${process.env['MONGO_PASSWORD'] ?? 'logixia_pass'}@` +
          `${process.env['MONGO_HOST'] ?? 'localhost'}:` +
          `${process.env['MONGO_PORT'] ?? 27017}/` +
          `${process.env['MONGO_DB'] ?? 'logixia_logs'}?authSource=admin`,
      database: process.env['MONGO_DB'] ?? 'logixia_logs',
      collection: 'logs',
      level: 'info',
      batchSize: 200,
      flushInterval: 3000,
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. DATABASE TRANSPORT — SQLite (great for dev / tests)
//
// Creates a single .db file — no server required.
// Schema matches PostgreSQL (minus JSONB → TEXT for payload).
// ─────────────────────────────────────────────────────────────────────────────
export const sqliteLogger = new LogixiaLogger({
  appName: 'DevApp',
  environment: 'development',
  level: 'debug',
  transports: {
    console: { colorize: true, timestamp: true },
    database: {
      type: 'sqlite',
      database: './dev-logs.db',   // file path for the SQLite database
      table: 'logs',
      batchSize: 20,
      flushInterval: 2000,
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 8. DATABASE TRANSPORT — MySQL
// ─────────────────────────────────────────────────────────────────────────────
export const mysqlLogger = new LogixiaLogger({
  appName: 'MyService',
  environment: 'production',
  level: 'info',
  transports: {
    database: {
      type: 'mysql',
      host: process.env['MYSQL_HOST'] ?? 'localhost',
      port: Number(process.env['MYSQL_PORT'] ?? 3306),
      database: process.env['MYSQL_DB'] ?? 'app_logs',
      username: process.env['MYSQL_USER'] ?? 'root',
      password: process.env['MYSQL_PASSWORD'] ?? '',
      table: 'logs',
      ssl: process.env['NODE_ENV'] === 'production',
      batchSize: 100,
      flushInterval: 5000,
    },
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 9. ALL TRANSPORTS TOGETHER
//
// Production pattern used by the NestJS example app (verified in Docker):
//   - Console:  colorized for humans
//   - File:     JSON rolling log for log shippers (Filebeat, Fluentd)
//   - Postgres: WARN+ for alerting / dashboards
//   - Mongo:    INFO+ for full search / analytics
// ─────────────────────────────────────────────────────────────────────────────
export const fullStackLogger = new LogixiaLogger({
  appName: 'MyService',
  environment: (process.env['NODE_ENV'] ?? 'development') as 'development' | 'production',
  level: 'debug',

  transports: {
    console: {
      colorize: true,
      timestamp: true,
      level: 'debug',
    },

    file: {
      filename: 'app.log',
      dirname: process.env['LOG_FILE_DIR'] ?? './logs',
      format: 'json',
      level: 'info',
      batchSize: 100,
      flushInterval: 5000,
      rotation: {
        interval: '1d',
        maxFiles: 14,
        compress: true,
      },
    },

    database: [
      // Postgres: warn+ only (for PagerDuty / alerting)
      {
        type: 'postgresql',
        host: process.env['POSTGRES_HOST'] ?? 'localhost',
        port: Number(process.env['POSTGRES_PORT'] ?? 5432),
        database: process.env['POSTGRES_DB'] ?? 'logixia_logs',
        username: process.env['POSTGRES_USER'] ?? 'logixia',
        password: process.env['POSTGRES_PASSWORD'] ?? 'logixia_pass',
        table: 'logs',
        level: 'warn',
        batchSize: 50,
        flushInterval: 10000,
      },
      // Mongo: info+ (full log search)
      {
        type: 'mongodb',
        connectionString:
          `mongodb://${process.env['MONGO_USER'] ?? 'logixia'}:` +
          `${process.env['MONGO_PASSWORD'] ?? 'logixia_pass'}@` +
          `${process.env['MONGO_HOST'] ?? 'localhost'}:` +
          `${process.env['MONGO_PORT'] ?? 27017}/` +
          `${process.env['MONGO_DB'] ?? 'logixia_logs'}?authSource=admin`,
        database: process.env['MONGO_DB'] ?? 'logixia_logs',
        collection: 'logs',
        level: 'info',
        batchSize: 200,
        flushInterval: 3000,
      },
    ],
  },

  // Automatically flush all transports on SIGTERM / SIGINT — verified in Docker
  // (dumb-init forwards the signal; gracefulShutdown ensures no log loss)
  gracefulShutdown: {
    enabled: true,
    timeout: 8000,   // wait up to 8s for in-flight batches to drain
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 10. MANUAL FileTransport — instantiated directly (no LogixiaLogger wrapper)
//
// Useful when you want to wire transport into your own log pipeline.
// ─────────────────────────────────────────────────────────────────────────────
export const rawFileTransport = new FileTransport({
  filename: 'raw.log',
  dirname: './logs/raw',
  format: 'json',
  batchSize: 1,            // write immediately (no batching)
  rotation: {
    interval: '1h',
    maxFiles: 24,
  },
});

// ─────────────────────────────────────────────────────────────────────────────
// 11. MANUAL DatabaseTransport — instantiated directly
// ─────────────────────────────────────────────────────────────────────────────
export const rawDbTransport = new DatabaseTransport({
  type: 'postgresql',
  host: 'localhost',
  port: 5432,
  database: 'logixia_logs',
  username: 'logixia',
  password: 'logixia_pass',
  table: 'logs',
  batchSize: 100,
  flushInterval: 5000,
});

// ─────────────────────────────────────────────────────────────────────────────
// DEMO — run all scenarios
// ─────────────────────────────────────────────────────────────────────────────
async function runDemo() {
  // Use a dedicated demo logger that writes immediately (batchSize 1)
  const logger = new LogixiaLogger({
    appName: 'TransportDemo',
    environment: 'development',
    level: 'debug',
    transports: {
      console: { colorize: true, timestamp: true },
      file: {
        filename: 'demo.log',
        dirname: './logs/json',
        format: 'json',
        level: 'debug',
        batchSize: 1,          // write immediately — no timer needed
        rotation: {
          interval: '1d',
          maxFiles: 7,
        },
      },
    },
  });

  // ── File: all formats ────────────────────────────────────────────────────
  logger.info('Application started', { pid: process.pid, node: process.version });
  logger.debug('Config loaded', { env: 'production', region: 'ap-south-1' });
  logger.warn('High memory usage', { heapUsedMb: 512, heapTotalMb: 768 });
  logger.error('Unhandled rejection', {
    error: { name: 'TypeError', message: 'Cannot read properties of undefined' },
  });

  // ── Child loggers (inherit transports) ───────────────────────────────────
  const dbLog = logger.child('DatabaseLayer');
  const httpLog = logger.child('HttpLayer');

  dbLog.info('Query executed', { sql: 'SELECT * FROM users', durationMs: 12 });
  httpLog.info('Request handled', { method: 'GET', url: '/api/users', statusCode: 200 });

  // ── timeAsync — measures and logs async operation duration ───────────────
  await logger.timeAsync('fetchUsers', async () => {
    await new Promise<void>((r) => setTimeout(r, 50));
    logger.info('Users fetched from DB', { count: 42 });
  });

  // ── Check file was written ────────────────────────────────────────────────
  const logDir = './logs/json';
  if (fs.existsSync(logDir)) {
    const files = fs.readdirSync(logDir);
    console.log(`\nFile transport output (${logDir}):`);
    for (const f of files) {
      const size = fs.statSync(path.join(logDir, f)).size;
      console.log(`  ${f}  (${size} bytes)`);
    }
    if (files.length > 0) {
      const latest = files.sort().at(-1)!;
      const firstLine = fs.readFileSync(path.join(logDir, latest), 'utf8').split('\n')[0];
      console.log(`\nFirst log line (JSON):\n  ${firstLine}`);
    }
  }

  // ── Flush and close all transports ───────────────────────────────────────
  await logger.close();
  console.log('\nAll transports flushed and closed cleanly.');
}

if (require.main === module) {
  runDemo().catch(console.error);
}
