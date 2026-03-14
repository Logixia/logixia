# logixia

**Structured logging for TypeScript applications — console, file, database, and analytics transports with NestJS support, log search, request tracing, and OpenTelemetry out of the box.**

[![npm version](https://img.shields.io/npm/v/logixia)](https://www.npmjs.com/package/logixia)
[![npm downloads](https://img.shields.io/npm/dm/logixia)](https://www.npmjs.com/package/logixia)
[![CI](https://github.com/Logixia/logixia/actions/workflows/ci.yml/badge.svg)](https://github.com/Logixia/logixia/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0%2B-blue)](https://www.typescriptlang.org/)

---

## Why logixia?

`console.log` doesn't scale. `winston` is synchronous and gets complex fast. `pino` is fast but leaves transport configuration, database persistence, NestJS integration, log search, and field redaction entirely up to you.

logixia ships all of that as first-class features:

- **Async by design.** Every log call is non-blocking — your application thread is never held up by a slow transport.
- **Multi-transport.** Write to console, files, and databases concurrently with a single log call.
- **Built-in database transports.** Native MongoDB, PostgreSQL, MySQL, and SQLite — no extra adapters.
- **NestJS module.** Plug in with `LogixiaLoggerModule.forRoot(config)` and inject with `@InjectLogger()`.
- **Log search.** Query your logs in memory without shipping them to an external service.
- **Field redaction.** Mask sensitive fields (passwords, tokens, PII) before they reach any transport.
- **Request tracing.** Async context propagation via `AsyncLocalStorage` — trace IDs flow through your entire request lifecycle automatically.
- **OpenTelemetry.** W3C `traceparent` / `tracestate` support with zero extra dependencies.
- **Graceful shutdown.** `flushOnExit()` drains all transports before the process exits.
- **Adaptive log level.** Automatically adjusts based on `NODE_ENV` and CI environment detection.

---

## Installation

```bash
npm install logixia
```

For database transports, install the relevant driver:

```bash
npm install mongodb           # MongoDB
npm install pg                # PostgreSQL
npm install mysql2            # MySQL
npm install sqlite3 sqlite    # SQLite
```

---

## Quick start

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({ appName: 'api', environment: 'production' });

await logger.info('Server started', { port: 3000 });
await logger.warn('High memory usage', { used: '87%' });
await logger.error('Request failed', new Error('Connection timeout'));
```

---

## Core concepts

### Log levels

logixia ships with `trace`, `debug`, `info`, `warn`, `error`, and `fatal`. You can define custom levels for your application:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  levelOptions: {
    level: 'info',
    customLevels: {
      audit: { priority: 35, color: 'blue' },
    },
  },
});

await logger.log('audit', 'Payment processed', { amount: 99.99 });
```

### Structured logging

Every log call accepts an optional metadata object as the second argument. The metadata is serialized as structured data alongside the message — not concatenated into a string.

```typescript
await logger.info('User authenticated', {
  userId: 'usr_123',
  method: 'oauth',
  provider: 'google',
  durationMs: 42,
});
```

### Child loggers

Create child loggers that inherit context and add their own:

```typescript
const reqLogger = logger.child({ requestId: req.id, userId: req.user.id });
await reqLogger.info('Processing order');
```

---

## Transports

### Console

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'development',
  console: {
    colorize: true,
    timestamp: true,
    format: 'text', // or 'json'
  },
});
```

### File with rotation

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  file: {
    filename: 'app.log',
    dirname: './logs',
    maxSize: '50MB',
    maxFiles: 14,
    zippedArchive: true,
    format: 'json',
  },
});
```

### Database

```typescript
// PostgreSQL
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  database: {
    type: 'postgresql',
    host: 'localhost',
    port: 5432,
    database: 'appdb',
    table: 'logs',
    username: 'dbuser',
    password: process.env.DB_PASSWORD,
    batchSize: 100,
    flushInterval: 5000,
  },
});

// MongoDB
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  database: {
    type: 'mongodb',
    connectionString: process.env.MONGO_URI,
    database: 'appdb',
    collection: 'logs',
  },
});
```

### Multiple transports

A single logger can write to any number of destinations simultaneously:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  console: { colorize: false, format: 'json' },
  file: { filename: 'app.log', dirname: './logs', maxSize: '100MB' },
  database: { type: 'postgresql', host: 'localhost', database: 'appdb', table: 'logs' },
});
```

### Custom transport

```typescript
import type { ITransport, TransportLogEntry } from 'logixia';

class SlackTransport implements ITransport {
  name = 'slack';

  async write(entry: TransportLogEntry): Promise<void> {
    if (entry.level !== 'error') return;
    await fetch(process.env.SLACK_WEBHOOK_URL!, {
      method: 'POST',
      body: JSON.stringify({ text: `[ERROR] ${entry.message}` }),
    });
  }
}
```

---

## Request tracing

logixia uses `AsyncLocalStorage` so trace IDs propagate automatically through the entire async call graph without passing them explicitly.

```typescript
import { runWithTraceId, getCurrentTraceId } from 'logixia';

// Express middleware
app.use((req, res, next) => {
  const traceId = (req.headers['x-trace-id'] as string) ?? generateTraceId();
  runWithTraceId(traceId, next);
});

// Anywhere in the call chain — no extra parameters needed
await logger.info('Processing payment'); // trace ID is included automatically
```

---

## NestJS integration

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'nestjs-app',
      environment: process.env.NODE_ENV ?? 'development',
      console: { colorize: true },
    }),
  ],
})
export class AppModule {}

// my.service.ts
import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService } from 'logixia';

@Injectable()
export class MyService {
  constructor(private readonly logger: LogixiaLoggerService) {}

  async doWork() {
    await this.logger.info('Doing work');
  }
}
```

---

## Log redaction

Redact sensitive fields before they reach any transport:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  redaction: {
    paths: ['password', 'token', 'creditCard', 'ssn', '*.secret'],
    censor: '[REDACTED]',
  },
});

await logger.info('User payload', {
  username: 'alice',
  password: 'supersecret', // becomes '[REDACTED]'
  token: 'eyJhbGc...', // becomes '[REDACTED]'
});
```

---

## Log search

Query logs in memory without an external service:

```typescript
import { SearchManager } from 'logixia';

const search = new SearchManager();
await search.index(logEntries);

const results = await search.search({
  query: 'payment failed',
  level: 'error',
  from: new Date('2025-01-01'),
  to: new Date(),
  limit: 50,
});
```

---

## Graceful shutdown

```typescript
import { flushOnExit } from 'logixia';

flushOnExit(logger); // drains all transports before process.exit
```

---

## Feature comparison

| Feature                             | logixia |      pino       |            winston            |
| ----------------------------------- | :-----: | :-------------: | :---------------------------: |
| TypeScript-first                    |   Yes   |     Partial     |            Partial            |
| Async / non-blocking                |   Yes   |       No        |              No               |
| NestJS module                       |   Yes   |       No        |              No               |
| Database transports (built-in)      |   Yes   |       No        |              No               |
| Multi-transport (concurrent)        |   Yes   |       No        |              Yes              |
| File rotation (built-in)            |   Yes   |  via pino-roll  | via winston-daily-rotate-file |
| Log search                          |   Yes   |       No        |              No               |
| Field redaction                     |   Yes   | via pino-redact |              No               |
| Request tracing (AsyncLocalStorage) |   Yes   |       No        |              No               |
| OpenTelemetry (W3C)                 |   Yes   |       No        |              No               |
| Graceful shutdown                   |   Yes   |       No        |              No               |
| Custom log levels                   |   Yes   |       Yes       |              Yes              |
| Adaptive log level (NODE_ENV)       |   Yes   |       No        |              No               |

---

## Performance

logixia uses `async/await` throughout — log calls are non-blocking by design, so your application threads are never stalled by slow transports (file I/O, network, database). This is a deliberate trade-off: slightly higher per-call overhead in exchange for zero event-loop blocking.

Benchmark on Node.js v22 (mocked transport — measures framework overhead only):

| Library | Simple log (ops/sec) | Structured log (ops/sec) | p99 latency |
| ------- | -------------------: | -----------------------: | ----------: |
| pino    |            1,233,000 |                  619,000 |       3–5µs |
| winston |              754,000 |                  374,000 |      9–21µs |
| logixia |              240,000 |                  203,000 |     19–24µs |

pino's throughput lead is expected — it uses synchronous serialization. When you factor in actual transport I/O (file write, DB insert), the differences narrow significantly. If raw throughput is your only concern and you need none of logixia's features, pino is the right choice.

To reproduce: `node benchmarks/run.mjs`

---

## Configuration reference

```typescript
interface LoggerConfig {
  appName: string;
  environment: string;
  silent?: boolean; // Disable all output (useful in tests)
  levelOptions?: {
    level?: LogLevelString; // Minimum level to log
    customLevels?: Record<string, { priority: number; color: string }>;
    namespaces?: Record<string, string>; // Per-namespace overrides
  };
  redaction?: {
    paths: string[];
    censor?: string;
  };
  gracefulShutdown?: {
    enabled?: boolean;
    timeout?: number;
  };
  console?: ConsoleTransportConfig;
  file?: FileTransportConfig;
  database?: DatabaseTransportConfig;
  analytics?: AnalyticsTransportConfig;
}
```

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss the approach.

```bash
git clone https://github.com/Logixia/logixia.git
cd logixia
npm install
npm test
```

---

## License

MIT
