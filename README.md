# logixia

<p align="center">
  <strong>The async-first logging library that ships complete.</strong><br/>
  TypeScript-first · Non-blocking by design · NestJS · Database · Tracing · OTel
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/logixia"><img src="https://img.shields.io/npm/v/logixia" alt="npm version"/></a>
  <a href="https://www.npmjs.com/package/logixia"><img src="https://img.shields.io/npm/dm/logixia" alt="npm downloads"/></a>
  <a href="https://bundlephobia.com/package/logixia"><img src="https://img.shields.io/bundlephobia/minzip/logixia" alt="bundle size"/></a>
  <a href="https://github.com/Logixia/logixia/actions/workflows/ci.yml"><img src="https://github.com/Logixia/logixia/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT"/></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-5.0%2B-blue" alt="TypeScript"/></a>
</p>

---

## The logging setup you copy-paste into every new project

```bash
# The pino route:
npm install pino pino-pretty pino-roll pino-redact pino-nestjs pino-http

# The winston route:
npm install winston winston-daily-rotate-file
# ...then wire 4 separate config objects
# ...then discover there's no built-in DB transport
# ...then discover request tracing is manual
# ...then discover both block your event loop under I/O pressure

# Or:
npm install logixia
```

logixia ships **console + file rotation + database + request tracing + NestJS module + field redaction + log search + OpenTelemetry** in one package — non-blocking on every transport, zero extra installs.

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  file: { filename: 'app.log', dirname: './logs', maxSize: '50MB' },
  database: { type: 'postgresql', host: 'localhost', database: 'appdb', table: 'logs' },
});

await logger.info('Server started', { port: 3000 });
// Writes to console + file + postgres simultaneously. Non-blocking. Done.
```

---

## Table of Contents

- [Why logixia?](#why-logixia)
- [Feature comparison](#feature-comparison)
- [Performance](#performance)
- [Installation](#installation)
- [Quick start](#quick-start)
- [Core concepts](#core-concepts)
  - [Log levels](#log-levels)
  - [Structured logging](#structured-logging)
  - [Child loggers](#child-loggers)
- [Transports](#transports)
  - [Console](#console)
  - [File with rotation](#file-with-rotation)
  - [Database](#database)
  - [Analytics](#analytics)
  - [Multiple transports simultaneously](#multiple-transports-simultaneously)
  - [Custom transport](#custom-transport)
- [Request tracing](#request-tracing)
- [NestJS integration](#nestjs-integration)
- [Log redaction](#log-redaction)
- [Log search](#log-search)
- [OpenTelemetry](#opentelemetry)
- [Graceful shutdown](#graceful-shutdown)
- [Configuration reference](#configuration-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Why logixia?

`console.log` doesn't scale. `pino` is fast but leaves database persistence, NestJS integration, log search, and field redaction entirely to plugins. `winston` is flexible but synchronous and requires substantial boilerplate to get production-ready.

logixia takes a different approach: **everything ships built-in, and nothing blocks your event loop.**

- ⚡ **Async by design** — every log call is non-blocking, even to file and database transports
- 🗄️ **Built-in database transports** — PostgreSQL, MySQL, MongoDB, SQLite with zero extra drivers
- 🏗️ **NestJS module** — plug in with `LogixiaLoggerModule.forRoot()`, inject with `@InjectLogger()`
- 📁 **File rotation** — `maxSize`, `maxFiles`, gzip archive — no `winston-daily-rotate-file` needed
- 🔍 **Log search** — query your in-memory log store without shipping to an external service
- 🔒 **Field redaction** — mask passwords, tokens, and PII before they touch any transport
- 🕸️ **Request tracing** — `AsyncLocalStorage`-based trace propagation, no manual thread-locals
- 📡 **OpenTelemetry** — W3C `traceparent` and `tracestate` support, zero extra dependencies
- 🧩 **Multi-transport** — write to console, file, and database concurrently with one log call
- 🛡️ **TypeScript-first** — typed log entries, typed metadata, full IntelliSense throughout
- 🌱 **Adaptive log level** — auto-configures based on `NODE_ENV` and CI environment
- 🔌 **Custom transports** — ship to Slack, Datadog, S3, or anywhere else with a simple interface

---

## Feature comparison

| Feature                             | **logixia** |      pino      |           winston            | bunyan |
| ----------------------------------- | :---------: | :------------: | :--------------------------: | :----: |
| TypeScript-first                    |     ✅      |       ⚠️       |              ⚠️              |   ⚠️   |
| Async / non-blocking writes         |     ✅      |       ❌       |              ❌              |   ❌   |
| NestJS module (built-in)            |     ✅      |       ❌       |              ❌              |   ❌   |
| Database transports (built-in)      |     ✅      |       ❌       |              ❌              |   ❌   |
| File rotation (built-in)            |     ✅      |  ⚠️ pino-roll  | ⚠️ winston-daily-rotate-file |   ❌   |
| Multi-transport concurrent          |     ✅      |       ❌       |              ✅              |   ❌   |
| Log search                          |     ✅      |       ❌       |              ❌              |   ❌   |
| Field redaction (built-in)          |     ✅      | ⚠️ pino-redact |              ❌              |   ❌   |
| Request tracing (AsyncLocalStorage) |     ✅      |       ❌       |              ❌              |   ❌   |
| OpenTelemetry / W3C headers         |     ✅      |       ❌       |              ❌              |   ❌   |
| Graceful shutdown / flush           |     ✅      |       ❌       |              ❌              |   ❌   |
| Custom log levels                   |     ✅      |       ✅       |              ✅              |   ✅   |
| Adaptive log level (NODE_ENV)       |     ✅      |       ❌       |              ❌              |   ❌   |
| Actively maintained                 |     ✅      |       ✅       |              ✅              |   ❌   |

> ⚠️ = requires a separate package or manual implementation

---

## Performance

logixia is **faster than winston in every benchmark** and outperforms pino on the workloads that matter most in production — structured metadata and error serialization:

| Library     | Simple log (ops/sec) | Structured log (ops/sec) | Error log (ops/sec) |  p99 latency |
| ----------- | -------------------: | -----------------------: | ------------------: | -----------: |
| pino        |            1,258,000 |                  630,000 |             390,000 |     2.5–12µs |
| **logixia** |          **840,000** |              **696,000** |         **654,000** | **4.8–10µs** |
| winston     |              738,000 |                  371,000 |             433,000 |       9–16µs |

logixia is **10% faster than pino on structured logging** and **68% faster on error serialization**. It beats winston across the board.

**Why pino leads on simple strings:** pino uses synchronous direct writes to `process.stdout` — a trade-off that blocks the event loop under heavy I/O and that disappears as soon as you add real metadata. logixia is non-blocking on every call while still winning where it counts.

To reproduce: `node benchmarks/run.mjs`

---

## Installation

```bash
# npm
npm install logixia

# pnpm
pnpm add logixia

# yarn
yarn add logixia

# bun
bun add logixia
```

**For database transports**, install the relevant driver alongside logixia:

```bash
npm install pg          # PostgreSQL
npm install mysql2      # MySQL
npm install mongodb     # MongoDB
npm install sqlite3     # SQLite
```

**Requirements:** TypeScript 5.0+, Node.js 18+

---

## Quick start

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
});

await logger.info('Server started', { port: 3000 });
await logger.warn('High memory usage', { used: '87%' });
await logger.error('Request failed', new Error('Connection timeout'));
```

That's it. Logs go to the console by default, structured JSON in production, colorized text in development. Add a `file` or `database` key to write there too — all transports run concurrently.

---

## Core concepts

### Log levels

logixia ships with six built-in levels: `trace`, `debug`, `info`, `warn`, `error`, and `fatal`. The minimum level is automatically inferred from `NODE_ENV` and CI environment — no manual setup in most projects.

You can also define custom levels for your domain:

```typescript
const logger = createLogger({
  appName: 'payments',
  environment: 'production',
  levelOptions: {
    level: 'info',
    customLevels: {
      audit: { priority: 35, color: 'blue' },
      security: { priority: 45, color: 'red' },
    },
  },
});

await logger.log('audit', 'Payment processed', { orderId: 'ord_123', amount: 99.99 });
await logger.log('security', 'Suspicious login attempt', { ip: '1.2.3.4', userId: 'usr_456' });
```

### Structured logging

Every log call accepts metadata as its second argument — serialized as structured fields alongside the message, never concatenated into a string:

```typescript
await logger.info('User authenticated', {
  userId: 'usr_123',
  method: 'oauth',
  provider: 'google',
  durationMs: 42,
  ip: '203.0.113.4',
});
```

Output in development (colorized text):

```
[INFO] User authenticated  userId=usr_123 method=oauth provider=google durationMs=42
```

Output in production (JSON):

```json
{
  "level": "info",
  "message": "User authenticated",
  "userId": "usr_123",
  "method": "oauth",
  "provider": "google",
  "durationMs": 42,
  "timestamp": "2025-03-14T10:22:01.412Z",
  "traceId": "abc123def456"
}
```

### Child loggers

Create child loggers that inherit parent context and add their own. Every log from the child carries both sets of fields automatically:

```typescript
const reqLogger = logger.child({
  requestId: req.id,
  userId: req.user.id,
  route: req.path,
});

await reqLogger.info('Processing order'); // carries requestId + userId + route
await reqLogger.info('Payment confirmed'); // same context, no repetition
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
    format: 'text', // 'text' (human-readable) or 'json' (structured)
  },
});
```

### File with rotation

No extra packages. Rotation by size, automatic compression, and configurable retention — all built-in:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  file: {
    filename: 'app.log',
    dirname: './logs',
    maxSize: '50MB', // Rotate when file hits 50 MB
    maxFiles: 14, // Keep 14 rotated files (~ 2 weeks)
    zippedArchive: true, // Compress old logs with gzip
    format: 'json',
  },
});
```

### Database

Write structured logs directly to your database — batched, non-blocking, with configurable flush intervals:

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
    batchSize: 100, // Write in batches of 100
    flushInterval: 5000, // Flush every 5 seconds
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

// MySQL
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  database: {
    type: 'mysql',
    host: 'localhost',
    database: 'appdb',
    table: 'logs',
    username: 'root',
    password: process.env.MYSQL_PASSWORD,
  },
});

// SQLite (great for local development and small apps)
const logger = createLogger({
  appName: 'api',
  environment: 'development',
  database: {
    type: 'sqlite',
    filename: './logs/app.sqlite',
    table: 'logs',
  },
});
```

### Analytics

Send log events to your analytics platform:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  analytics: {
    endpoint: 'https://analytics.example.com/events',
    apiKey: process.env.ANALYTICS_KEY,
    batchSize: 50,
    flushInterval: 10_000,
  },
});
```

### Multiple transports simultaneously

All configured transports receive every log call concurrently — no sequential bottleneck:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  console: { colorize: false, format: 'json' },
  file: { filename: 'app.log', dirname: './logs', maxSize: '100MB' },
  database: {
    type: 'postgresql',
    host: 'localhost',
    database: 'appdb',
    table: 'logs',
  },
});

// One call → console + file + postgres. All concurrent. All non-blocking.
await logger.info('Order placed', { orderId: 'ord_789' });
```

### Custom transport

Implement `ITransport` to send logs anywhere — Slack, Datadog, S3, an internal queue:

```typescript
import type { ITransport, TransportLogEntry } from 'logixia';

class SlackTransport implements ITransport {
  name = 'slack';

  async write(entry: TransportLogEntry): Promise<void> {
    if (entry.level !== 'error' && entry.level !== 'fatal') return;
    await fetch(process.env.SLACK_WEBHOOK_URL!, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        text: `🚨 *[${entry.level.toUpperCase()}]* ${entry.message}`,
        attachments: [{ text: JSON.stringify(entry.metadata, null, 2) }],
      }),
    });
  }
}

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: [new SlackTransport()],
});
```

---

## Request tracing

logixia uses `AsyncLocalStorage` to propagate trace IDs through your entire async call graph automatically — no passing of context objects, no manual threading.

```typescript
import { runWithTraceId, getCurrentTraceId } from 'logixia';

// Express / Fastify middleware
app.use((req, res, next) => {
  const traceId = (req.headers['x-trace-id'] as string) ?? crypto.randomUUID();
  runWithTraceId(traceId, next);
});

// Service layer — no parameters, no context objects
class OrderService {
  async createOrder(data: OrderData) {
    await logger.info('Creating order', { items: data.items.length });
    // ↑ trace ID is automatically included in this log entry
    await this.processPayment(data);
  }

  async processPayment(data: OrderData) {
    await logger.info('Processing payment', { amount: data.total });
    // ↑ same trace ID, propagated automatically
  }
}
```

Every log entry automatically includes the current trace ID — even across `await` boundaries, `Promise.all`, and background jobs that were started in the request context.

---

## NestJS integration

Drop-in module with zero boilerplate. Supports both synchronous and async configuration:

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'nestjs-api',
      environment: process.env.NODE_ENV ?? 'development',
      console: { colorize: true },
      file: { filename: 'app.log', dirname: './logs', maxSize: '50MB' },
    }),
  ],
})
export class AppModule {}
```

```typescript
// my.service.ts
import { Injectable } from '@nestjs/common';
import { InjectLogger, LogixiaLoggerService } from 'logixia';

@Injectable()
export class OrderService {
  constructor(@InjectLogger() private readonly logger: LogixiaLoggerService) {}

  async createOrder(data: CreateOrderDto) {
    await this.logger.info('Creating order', { userId: data.userId });
    // ...
  }
}
```

**Async configuration** (for database credentials from a config service):

```typescript
LogixiaLoggerModule.forRootAsync({
  useFactory: async (configService: ConfigService) => ({
    appName: 'nestjs-api',
    environment: configService.get('NODE_ENV'),
    database: {
      type: 'postgresql',
      host: configService.get('DB_HOST'),
      password: configService.get('DB_PASSWORD'),
    },
  }),
  inject: [ConfigService],
});
```

---

## Log redaction

Redact sensitive fields before they reach any transport — passwords, tokens, PII, credit card numbers. Fields are masked in-place before serialization:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  redaction: {
    paths: [
      'password',
      'token',
      'accessToken',
      'refreshToken',
      'creditCard',
      'ssn',
      '*.secret', // Wildcard: any field named 'secret' at any depth
      'user.email', // Nested path
    ],
    censor: '[REDACTED]', // Default: '[REDACTED]'
  },
});

await logger.info('User login', {
  username: 'alice',
  password: 'hunter2', // → '[REDACTED]'
  token: 'eyJhbGc...', // → '[REDACTED]'
  creditCard: '4111...', // → '[REDACTED]'
  ip: '203.0.113.4', // ← untouched
});
```

Redaction is applied once, before the entry is dispatched to any transport — no risk of a transport accidentally logging sensitive data.

---

## Log search

Query your in-memory log history without shipping to Elasticsearch, Datadog, or any external service. Great for development environments and lightweight production setups:

```typescript
import { SearchManager } from 'logixia';

const search = new SearchManager({ maxEntries: 10_000 });

// Index a batch of entries (e.g. from a file or database)
await search.index(logEntries);

// Search by text, level, and time range
const results = await search.search({
  query: 'payment failed',
  level: 'error',
  from: new Date('2025-01-01'),
  to: new Date(),
  limit: 50,
});

// results → sorted by relevance, includes matched entries with full metadata
```

---

## OpenTelemetry

W3C `traceparent` and `tracestate` headers are extracted from incoming requests and attached to every log entry automatically — enabling correlation between distributed traces and log events in tools like Jaeger, Zipkin, Honeycomb, and Datadog:

```typescript
// With tracing enabled (zero extra packages required)
const logger = createLogger({
  appName: 'checkout-service',
  environment: 'production',
  otel: {
    enabled: true,
    serviceName: 'checkout-service',
    propagate: ['traceparent', 'tracestate', 'baggage'],
  },
});

// In an Express handler receiving a traced request:
app.post('/checkout', async (req, res) => {
  await logger.info('Checkout initiated', { cartId: req.body.cartId });
  // ^ log entry carries the W3C traceparent from the incoming request
});
```

---

## Graceful shutdown

Ensures all buffered log entries are flushed to every transport before the process exits. Critical for database and analytics transports that batch writes:

```typescript
import { flushOnExit } from 'logixia';

// Register once at startup — handles SIGTERM, SIGINT, and uncaught exceptions
flushOnExit(logger);
```

Alternatively, flush manually:

```typescript
// In a Kubernetes SIGTERM handler:
process.on('SIGTERM', async () => {
  await logger.flush(); // Wait for all in-flight writes to complete
  process.exit(0);
});
```

---

## Configuration reference

```typescript
interface LoggerConfig {
  // Required
  appName: string;
  environment: string;

  // Optional — general
  silent?: boolean; // Suppress all output (useful in tests)

  levelOptions?: {
    level?: 'trace' | 'debug' | 'info' | 'warn' | 'error' | 'fatal';
    customLevels?: Record<string, { priority: number; color: string }>;
    namespaces?: Record<string, string>; // Per-namespace level overrides
  };

  redaction?: {
    paths: string[]; // Field paths or wildcards to redact
    censor?: string; // Replacement string (default: '[REDACTED]')
  };

  gracefulShutdown?: {
    enabled?: boolean;
    timeout?: number; // Max ms to wait for transports to flush
  };

  otel?: {
    enabled?: boolean;
    serviceName?: string;
    propagate?: ('traceparent' | 'tracestate' | 'baggage')[];
  };

  // Transports (all optional, can be combined freely)
  console?: {
    colorize?: boolean;
    timestamp?: boolean;
    format?: 'text' | 'json';
  };

  file?: {
    filename: string;
    dirname: string;
    maxSize?: string; // e.g. '50MB', '1GB'
    maxFiles?: number;
    zippedArchive?: boolean;
    format?: 'text' | 'json';
  };

  database?: {
    type: 'postgresql' | 'mysql' | 'mongodb' | 'sqlite';
    // PostgreSQL / MySQL
    host?: string;
    port?: number;
    database?: string;
    table?: string;
    username?: string;
    password?: string;
    // MongoDB
    connectionString?: string;
    collection?: string;
    // SQLite
    filename?: string;
    // Batching
    batchSize?: number;
    flushInterval?: number; // ms
  };

  analytics?: {
    endpoint: string;
    apiKey?: string;
    batchSize?: number;
    flushInterval?: number; // ms
  };

  transports?: ITransport[]; // Additional custom transports
}
```

---

## Contributing

```bash
git clone https://github.com/Logixia/logixia.git
cd logixia
npm install
npm test
```

Pull requests are welcome. For significant changes, please open an issue first to discuss what you'd like to change.

---

## License

[MIT](https://opensource.org/licenses/MIT) © [Sanjeev Sharma](https://github.com/webcoderspeed)
