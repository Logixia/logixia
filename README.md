# logixia

<p align="center">
  <strong>The async-first logging library that ships complete.</strong><br/>
  TypeScript-first &middot; Non-blocking by design &middot; NestJS &middot; Database &middot; Cloud &middot; Tracing &middot; OTel &middot; Browser
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/logixia"><img src="https://img.shields.io/npm/v/logixia" alt="npm version"/></a>
  <a href="https://www.npmjs.com/package/logixia"><img src="https://img.shields.io/npm/dm/logixia" alt="npm downloads"/></a>
  <a href="https://bundlephobia.com/package/logixia"><img src="https://img.shields.io/bundlephobia/minzip/logixia" alt="bundle size"/></a>
  <a href="https://github.com/Logixia/logixia/actions/workflows/ci.yml"><img src="https://github.com/Logixia/logixia/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-blue.svg" alt="MIT"/></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-5.0%2B-blue" alt="TypeScript"/></a>
  <a href="https://logixia.github.io/logixia/"><img src="https://img.shields.io/badge/website-logixia.github.io-a855f7" alt="website"/></a>
</p>

<p align="center">
  <a href="https://logixia.github.io/logixia/"><strong>Website</strong></a> &middot;
  <a href="https://github.com/Logixia/logixia">GitHub</a> &middot;
  <a href="https://www.npmjs.com/package/logixia">npm</a> &middot;
  <a href="https://github.com/Logixia/logixia/issues">Issues</a>
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

logixia ships **console + file rotation + database + request tracing + NestJS module + field redaction + log search + OpenTelemetry + plugin API + Prometheus metrics + visual TUI explorer** in one package — non-blocking on every transport, zero extra installs.

```typescript
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    console: { format: 'json' },
    file: { filename: 'app.log', dirname: './logs', maxSize: '50MB' },
    database: { type: 'postgresql', host: 'localhost', database: 'appdb', table: 'logs' },
  },
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
  - [Adaptive log level](#adaptive-log-level)
  - [Per-namespace log levels](#per-namespace-log-levels)
- [Transports](#transports)
  - [Console](#console)
  - [File with rotation](#file-with-rotation)
  - [Database](#database)
  - [Analytics](#analytics)
  - [Multiple transports simultaneously](#multiple-transports-simultaneously)
  - [Custom transport](#custom-transport)
- [Cloud adapters](#cloud-adapters)
  - [AWS CloudWatch](#aws-cloudwatch)
  - [Google Cloud Logging](#google-cloud-logging)
  - [Azure Monitor](#azure-monitor)
- [Request tracing](#request-tracing)
  - [Core trace utilities](#core-trace-utilities)
  - [Express / Fastify middleware](#express--fastify-middleware)
  - [NestJS trace middleware](#nestjs-trace-middleware)
  - [Kafka trace interceptor](#kafka-trace-interceptor)
  - [WebSocket trace interceptor](#websocket-trace-interceptor)
- [NestJS integration](#nestjs-integration)
  - [@LogMethod decorator](#logmethod-decorator)
  - [LogixiaExceptionFilter](#logixiaexceptionfilter)
- [Correlation ID propagation](#correlation-id-propagation)
  - [Express middleware](#correlation-express-middleware)
  - [Fastify hook](#correlation-fastify-hook)
  - [Outbound fetch / axios](#outbound-fetch--axios)
  - [Kafka / SQS helpers](#kafka--sqs-helpers)
- [Browser support](#browser-support)
- [Log redaction](#log-redaction)
- [Timer API](#timer-api)
- [Field management](#field-management)
- [Transport level control](#transport-level-control)
- [Log search](#log-search)
- [OpenTelemetry](#opentelemetry)
- [Graceful shutdown](#graceful-shutdown)
- [Plugin / extension API](#plugin--extension-api)
  - [Writing a plugin](#writing-a-plugin)
  - [Registering plugins globally](#registering-plugins-globally)
  - [Per-logger plugins](#per-logger-plugins)
  - [Cancelling a log entry](#cancelling-a-log-entry)
- [Metrics → Prometheus](#metrics--prometheus)
  - [Quick start (counters)](#quick-start-counters)
  - [Histograms](#histograms)
  - [Gauges](#gauges)
  - [Exposing the /metrics endpoint](#exposing-the-metrics-endpoint)
  - [Metric configuration reference](#metric-configuration-reference)
- [Logger instance API](#logger-instance-api)
- [CLI tool](#cli-tool)
  - [explore — Visual TUI log explorer](#explore--visual-tui-log-explorer)
- [Configuration reference](#configuration-reference)
- [Contributing](#contributing)
- [License](#license)

---

## Why logixia?

`console.log` doesn't scale. `pino` is fast but leaves database persistence, NestJS integration, log search, and field redaction entirely to plugins. `winston` is flexible but synchronous and requires substantial boilerplate to get production-ready.

logixia takes a different approach: **everything ships built-in, and nothing blocks your event loop.**

- **Async by design** — every log call is non-blocking, even to file and database transports
- **Built-in database transports** — PostgreSQL, MySQL, MongoDB, SQLite with zero extra drivers
- **Cloud adapters** — AWS CloudWatch (EMF), Google Cloud Logging, and Azure Monitor out of the box
- **NestJS module** — plug in with `LogixiaLoggerModule.forRoot()`, inject anywhere in the DI tree; `@LogMethod()` for auto-logging method entry/exit
- **File rotation** — `maxSize`, `maxFiles`, gzip archive, time-based rotation — no extra packages needed
- **Log search** — query your in-memory log store without shipping to an external service
- **Field redaction** — mask passwords, tokens, and PII before they touch any transport; supports dot-notation paths and regex patterns
- **Request tracing** — `AsyncLocalStorage`-based trace propagation with no manual thread-locals; includes Kafka and WebSocket interceptors
- **Correlation ID propagation** — auto-generate and forward `X-Correlation-ID` through `fetch`, axios, Kafka, and SQS across microservice boundaries
- **Browser support** — tree-shakeable `logixia/browser` entry point with console and remote batch transports; no Node.js built-ins
- **OpenTelemetry** — W3C `traceparent` and `tracestate` support, zero extra dependencies
- **Multi-transport** — write to console, file, and database concurrently with one log call
- **TypeScript-first** — typed log entries, typed metadata, custom-level IntelliSense throughout
- **Adaptive log level** — auto-configures based on `NODE_ENV` and CI environment
- **Custom transports** — ship to Slack, PagerDuty, S3, or anywhere else via a simple interface
- **Plugin / extension API** — lifecycle hooks (`onInit`, `onLog`, `onError`, `onShutdown`); plugins can mutate or cancel log entries; register globally or per-logger
- **Prometheus metrics** — turn log events into counters, histograms, and gauges with zero code; expose `GET /metrics` in Prometheus text format; works with any HTTP framework
- **Visual TUI explorer** — `logixia explore` opens a full-screen terminal log browser with real-time search, level filtering, syntax-highlighted JSON detail panel, stack trace rendering, and one-key export to JSON / CSV / NDJSON

---

## Feature comparison

| Feature                              | **logixia** |    pino     |          winston          | bunyan  |
| ------------------------------------ | :---------: | :---------: | :-----------------------: | :-----: |
| TypeScript-first                     |     yes     |   partial   |          partial          | partial |
| Async / non-blocking writes          |     yes     |     no      |            no             |   no    |
| NestJS module (built-in)             |     yes     |     no      |            no             |   no    |
| Database transports (built-in)       |     yes     |     no      |            no             |   no    |
| Cloud transports (CW, GCP, Azure)    |     yes     |     no      |            no             |   no    |
| File rotation (built-in)             |     yes     |  pino-roll  | winston-daily-rotate-file |   no    |
| Multi-transport concurrent           |     yes     |     no      |            yes            |   no    |
| Log search                           |     yes     |     no      |            no             |   no    |
| Field redaction (built-in)           |     yes     | pino-redact |            no             |   no    |
| Request tracing (AsyncLocalStorage)  |     yes     |     no      |            no             |   no    |
| Kafka + WebSocket trace interceptors |     yes     |     no      |            no             |   no    |
| Correlation ID propagation           |     yes     |     no      |            no             |   no    |
| Browser / Edge / Bun / Deno support  |     yes     |   partial   |            no             |   no    |
| OpenTelemetry / W3C headers          |     yes     |     no      |            no             |   no    |
| Graceful shutdown / flush            |     yes     |     no      |            no             |   no    |
| Custom log levels                    |     yes     |     yes     |            yes            |   yes   |
| Adaptive log level (NODE_ENV)        |     yes     |     no      |            no             |   no    |
| Plugin / extension API               |     yes     |     no      |            no             |   no    |
| Prometheus metrics extraction        |     yes     |     no      |            no             |   no    |
| Visual TUI log explorer              |     yes     |     no      |            no             |   no    |
| Actively maintained                  |     yes     |     yes     |            yes            |   no    |

---

## Performance

logixia uses `fast-json-stringify` (a pre-compiled serializer) for JSON output, which is ~59% faster than `JSON.stringify`. The hot path — level check, redaction decision, and format — is optimised with pre-built caches built once on construction, not on every log call.

| Library     | Simple log (ops/sec) | Structured log (ops/sec) | Error log (ops/sec) |  p99 latency |
| ----------- | -------------------: | -----------------------: | ------------------: | -----------: |
| pino        |            1,258,000 |                  630,000 |             390,000 |     2.5–12µs |
| **logixia** |          **840,000** |              **696,000** |         **654,000** | **4.8–10µs** |
| winston     |              738,000 |                  371,000 |             433,000 |       9–16µs |

logixia is **10% faster than pino on structured logging** and **68% faster on error serialization**. It beats winston across the board. Pino leads on simple string logs because it uses synchronous direct writes to `process.stdout` — a trade-off that blocks the event loop under heavy I/O and disappears as soon as you add real metadata.

To reproduce: `node benchmarks/run.mjs`

---

## Installation

```bash
npm install logixia
pnpm add logixia
yarn add logixia
bun add logixia
```

For database transports, install the relevant driver alongside logixia:

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

// ✅ Structured data — machine-readable, searchable, alertable
await logger.info('Server started', { port: 3000 });
await logger.warn('High memory usage', { used: '87%', threshold: '80%' });
await logger.error('Request failed', { orderId: 'ord_123', retryable: true });

// ✅ Pass an Error object directly — logixia serializes the full cause chain
await logger.error(new Error('Connection timeout'));

// ❌ Avoid string interpolation — you lose structured fields
// await logger.info(`Server started on port ${port}`);
```

No `try/catch` needed — logixia swallows transport errors internally so a flaky DB or disk-full condition never crashes your app.

Without a `transports` key, logs go to stdout/stderr. Add a `transports` key to write to file, database, or anywhere else — all transports run concurrently.

There is also a pre-configured default instance you can import directly:

```typescript
import { logger } from 'logixia';

await logger.info('Ready');
```

---

## Core concepts

### Log levels

logixia ships with six built-in levels in priority order: `error`, `warn`, `info`, `debug`, `trace`, `verbose`. Logs at or above the configured minimum level are emitted; the rest are dropped.

```typescript
await logger.error('Something went wrong');
await logger.warn('Approaching rate limit', { remaining: 5 });
await logger.info('Order created', { orderId: 'ord_123' });
await logger.debug('Cache miss', { key: 'user:456' });
await logger.trace('Entering function', { fn: 'processPayment' });
await logger.verbose('Full request payload', { body: req.body });
```

The `error` method also accepts an `Error` object directly — the full cause chain and standard Node.js fields (`code`, `statusCode`, `errno`, `syscall`) are serialized automatically:

```typescript
await logger.error(new Error('Connection refused'));

// With extra metadata alongside:
await logger.error(new Error('Payment declined'), { orderId: 'ord_123', retryable: true });

// AggregateError is handled too:
const err = new AggregateError([new Error('A'), new Error('B')], 'Multiple failures');
await logger.error(err);
```

You can also define **custom levels** for your domain:

```typescript
const logger = createLogger({
  appName: 'payments',
  environment: 'production',
  levelOptions: {
    level: 'info',
    levels: {
      // extend the built-in set with your own
      audit: { priority: 35, color: 'blue' },
      security: { priority: 45, color: 'red' },
    },
  },
});

// Custom level methods are available immediately, fully typed
await logger.audit('Payment processed', { orderId: 'ord_123', amount: 99.99 });
await logger.security('Suspicious login attempt', { ip: '1.2.3.4', userId: 'usr_456' });

// Or use logLevel() for dynamic dispatch
await logger.logLevel('audit', 'Refund issued', { orderId: 'ord_123' });
```

### Structured logging

Every log call accepts a metadata object as its second argument — serialized as structured fields alongside the message, never concatenated into a string:

```typescript
await logger.info('User authenticated', {
  userId: 'usr_123',
  method: 'oauth',
  provider: 'google',
  durationMs: 42,
  ip: '203.0.113.4',
});
```

Development output (colorized text):

```
[2025-03-14T10:22:01.412Z] [INFO] [api] [abc123def456] User authenticated {"userId":"usr_123","method":"oauth",...}
```

Production output (JSON, via `format: { json: true }`):

```json
{
  "timestamp": "2025-03-14T10:22:01.412Z",
  "level": "info",
  "appName": "api",
  "environment": "production",
  "message": "User authenticated",
  "traceId": "abc123def456",
  "payload": { "userId": "usr_123", "method": "oauth", "provider": "google", "durationMs": 42 }
}
```

### Child loggers

Create child loggers that inherit their parent's configuration and transport setup, but carry their own context string and optional extra fields:

```typescript
const reqLogger = logger.child('OrderService', {
  requestId: req.id,
  userId: req.user.id,
});

await reqLogger.info('Processing order'); // includes requestId + userId in every entry
await reqLogger.info('Payment confirmed'); // same context, no repetition
```

### Adaptive log level

logixia automatically selects a sensible default level when no explicit level is configured:

| Condition              | Default level |
| ---------------------- | :-----------: |
| `NODE_ENV=development` |    `debug`    |
| `NODE_ENV=test`        |    `warn`     |
| `NODE_ENV=production`  |    `info`     |
| `CI=true`              |    `info`     |
| None of the above      |    `info`     |

You can override this at any time via the `LOGIXIA_LEVEL` environment variable:

```bash
LOGIXIA_LEVEL=debug node server.js
```

Or change it at runtime:

```typescript
logger.setLevel('debug');
console.log(logger.getLevel()); // 'debug'
```

### Per-namespace log levels

Child loggers use their context string as a **namespace**. You can pin different log levels to different namespaces in config, or override them with environment variables at runtime — without redeploying:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  namespaceLevels: {
    db: 'debug', // child('db') and child('db.queries') → DEBUG
    'db.*': 'debug', // wildcard: all db.* children
    'http.*': 'warn', // only warn+ from HTTP layer
    payment: 'trace', // full trace for payment namespace
  },
});

const dbLogger = logger.child('db'); // resolves to DEBUG
const httpLogger = logger.child('http.req'); // resolves to WARN
```

Environment variable overrides use the pattern `LOGIXIA_LEVEL_<NS>` where `<NS>` is the first segment of the namespace, uppercased:

```bash
# Override just the db namespace to trace, without changing anything else:
LOGIXIA_LEVEL_DB=trace node server.js

# Override the payment namespace:
LOGIXIA_LEVEL_PAYMENT=info node server.js
```

---

## Transports

All transports are configured under the `transports` key and run concurrently on every log call.

### Console

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'development',
  format: {
    colorize: true, // ANSI colour output
    timestamp: true, // include ISO timestamp
    json: false, // text format; set to true for JSON
  },
  transports: {
    console: {
      level: 'debug', // minimum level for this transport only
    },
  },
});
```

### File with rotation

No extra packages. Rotation by size or time interval, automatic gzip compression, configurable retention — all built-in:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    file: {
      filename: 'app.log',
      dirname: './logs',
      maxSize: '50MB', // rotate when file reaches this size
      maxFiles: 14, // keep 14 rotated files
      zippedArchive: true, // compress old files with gzip
      format: 'json', // 'json' | 'text' | 'csv'
      batchSize: 100, // buffer up to 100 entries before writing
      flushInterval: 2000, // flush buffer every 2 seconds
    },
  },
});
```

You can also use **time-based rotation** via the `rotation` sub-key:

```typescript
transports: {
  file: {
    filename: 'app.log',
    dirname: './logs',
    rotation: {
      interval: '1d',      // rotate daily: '1h' | '6h' | '12h' | '1d' | '1w'
      maxFiles: 30,
      compress: true,
    },
  },
},
```

Multiple file transports are supported — pass an array:

```typescript
transports: {
  file: [
    { filename: 'app.log',   dirname: './logs', format: 'json' },
    { filename: 'error.log', dirname: './logs', format: 'json', level: 'error' },
  ],
},
```

### Database

Write structured logs directly to your database — batched, non-blocking, with configurable flush intervals:

```typescript
// PostgreSQL
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    database: {
      type: 'postgresql',
      host: 'localhost',
      port: 5432,
      database: 'appdb',
      table: 'logs',
      username: 'dbuser',
      password: process.env.DB_PASSWORD,
      batchSize: 100, // write in batches of 100
      flushInterval: 5000, // flush every 5 seconds
    },
  },
});

// MongoDB
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    database: {
      type: 'mongodb',
      connectionString: process.env.MONGO_URI,
      database: 'appdb',
      collection: 'logs',
    },
  },
});

// MySQL
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    database: {
      type: 'mysql',
      host: 'localhost',
      database: 'appdb',
      table: 'logs',
      username: 'root',
      password: process.env.MYSQL_PASSWORD,
    },
  },
});

// SQLite — great for local development and small apps
const logger = createLogger({
  appName: 'api',
  environment: 'development',
  transports: {
    database: {
      type: 'sqlite',
      database: './logs/app.sqlite',
      table: 'logs',
    },
  },
});
```

Multiple database targets are supported — pass an array:

```typescript
transports: {
  database: [
    { type: 'postgresql', host: 'primary-db', database: 'appdb', table: 'logs' },
    { type: 'mongodb', connectionString: process.env.MONGO_URI, database: 'appdb', collection: 'logs' },
  ],
},
```

### Analytics

logixia includes built-in support for Datadog, Mixpanel, Segment, and Google Analytics. All analytics transports are batched and non-blocking.

**Datadog** — sends logs, metrics, and traces to your Datadog account:

```typescript
import { DataDogTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    analytics: {
      datadog: {
        apiKey: process.env.DD_API_KEY!,
        site: 'datadoghq.com', // or 'datadoghq.eu', 'us3.datadoghq.com'
        service: 'api',
        env: 'production',
        enableLogs: true,
        enableMetrics: true,
        enableTraces: true,
      },
    },
  },
});
```

**Mixpanel:**

```typescript
transports: {
  analytics: {
    mixpanel: {
      token: process.env.MIXPANEL_TOKEN!,
      enableSuperProperties: true,
      superProperties: { platform: 'web', version: '2.0' },
    },
  },
},
```

**Segment:**

```typescript
transports: {
  analytics: {
    segment: {
      writeKey: process.env.SEGMENT_WRITE_KEY!,
      enableBatching: true,
      flushAt: 20,
      flushInterval: 10_000,
    },
  },
},
```

**Google Analytics:**

```typescript
transports: {
  analytics: {
    googleAnalytics: {
      measurementId: process.env.GA_MEASUREMENT_ID!,
      apiSecret: process.env.GA_API_SECRET!,
      enableEcommerce: false,
    },
  },
},
```

### Multiple transports simultaneously

All configured transports receive every log entry concurrently — no sequential bottleneck:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    console: { format: 'json' },
    file: { filename: 'app.log', dirname: './logs', maxSize: '100MB' },
    database: {
      type: 'postgresql',
      host: 'localhost',
      database: 'appdb',
      table: 'logs',
    },
    analytics: {
      datadog: {
        apiKey: process.env.DD_API_KEY!,
        service: 'api',
      },
    },
  },
});

// One call → console + file + postgres + datadog. All concurrent. All non-blocking.
await logger.info('Order placed', { orderId: 'ord_789' });
```

### Custom transport

Implement `ITransport` to send logs anywhere — Slack, PagerDuty, S3, an internal queue:

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
        text: `*[${entry.level.toUpperCase()}]* ${entry.message}`,
        attachments: [{ text: JSON.stringify(entry.data, null, 2) }],
      }),
    });
  }

  async close(): Promise<void> {
    // optional cleanup
  }
}

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [new SlackTransport()],
  },
});
```

The `write` method may return `void` or `Promise<void>` — both are supported. The `TransportLogEntry` shape is:

```typescript
interface TransportLogEntry {
  timestamp: Date;
  level: string;
  message: string;
  data?: Record<string, unknown>;
  context?: string;
  traceId?: string;
  appName?: string;
  environment?: string;
}
```

---

## Cloud adapters

logixia ships three production-ready cloud transports. All are batched, non-blocking, and implement the same `flush()` / `close()` lifecycle as the built-in transports. Import and pass directly to the `custom` transport array.

### AWS CloudWatch

Batches log events and sends them to a CloudWatch Logs stream using `PutLogEvents`. Supports **EMF** (Embedded Metric Format) so numeric fields in your log entries are automatically promoted to CloudWatch Metrics — no separate SDK needed.

```typescript
import { CloudWatchTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [
      new CloudWatchTransport({
        region: 'us-east-1', // or set AWS_REGION env var
        logGroupName: '/app/api',
        logStreamName: 'api-server-1', // defaults to hostname + PID
        // Credentials fall back to AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars,
        // or the EC2/ECS/Lambda metadata service — no hard-coding needed.
        batchSize: 100, // default: 100
        flushIntervalMs: 5000, // default: 5000
        emf: true, // emit numeric fields as CloudWatch Metrics
        level: 'warn', // forward only warn+ to CloudWatch
      }),
    ],
  },
});
```

With `emf: true`, any numeric field in your log data is published as a CloudWatch Metric under the `Logixia` namespace:

```typescript
await logger.info('Request completed', { duration: 142, statusCode: 200 });
// → CloudWatch Metric: Logixia/duration, Logixia/statusCode
```

### Google Cloud Logging

Maps logixia levels to GCP `severity` values (`DEBUG`, `INFO`, `WARNING`, `ERROR`, `CRITICAL`), auto-injects `logging.googleapis.com/trace` for Cloud Trace correlation, and supports Application Default Credentials (ADC) — no service account JSON required when running on GKE / Cloud Run / App Engine.

```typescript
import { GCPTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [
      new GCPTransport({
        projectId: 'my-gcp-project', // or set GOOGLE_CLOUD_PROJECT env var
        logName: 'projects/my-gcp-project/logs/api',
        resource: { type: 'k8s_container', labels: { cluster_name: 'prod' } },
        // credentials: { client_email: '...', private_key: '...' }
        // Omit to use ADC (recommended on GCP-hosted infrastructure)
        batchSize: 200,
        flushIntervalMs: 5000,
      }),
    ],
  },
});
```

### Azure Monitor

Sends logs to Azure Monitor via the **Logs Ingestion API** (Data Collection Rule). Uses OAuth2 client-credentials to obtain a bearer token automatically.

```typescript
import { AzureMonitorTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [
      new AzureMonitorTransport({
        endpoint: 'https://<dce-name>.ingest.monitor.azure.com',
        ruleId: 'dcr-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
        streamName: 'Custom-LogixiaLogs_CL',
        tenantId: process.env.AZURE_TENANT_ID,
        clientId: process.env.AZURE_CLIENT_ID,
        clientSecret: process.env.AZURE_CLIENT_SECRET,
        batchSize: 200,
        flushIntervalMs: 5000,
      }),
    ],
  },
});
```

All three cloud transports expose `flush()` and `close()` so they participate in logixia's [graceful shutdown](#graceful-shutdown) flow automatically.

---

## Request tracing

logixia uses `AsyncLocalStorage` to propagate trace IDs through your entire async call graph automatically — no passing of context objects, no manual threading.

### Core trace utilities

```typescript
import {
  generateTraceId, // create a UUID v4 trace ID
  getCurrentTraceId, // read trace ID from current async context
  runWithTraceId, // run a callback inside a new trace context
  setTraceId, // set trace ID in the CURRENT context (use sparingly)
  extractTraceId, // extract a trace ID from a request-like object
} from 'logixia';

// Generate a new trace ID
const traceId = generateTraceId();
// → 'a3f1c2b4-...'

// Run code inside a trace context — every logger.* call within the callback
// (including across await boundaries and Promise.all) will carry this trace ID
runWithTraceId(traceId, async () => {
  await logger.info('Processing job'); // traceId attached automatically
  await processItems(); // all nested async calls carry it too
});

// Read the trace ID currently in context (returns undefined if none is set)
const current = getCurrentTraceId();

// Extract a trace ID from an incoming request object
const incomingTraceId = extractTraceId(req, {
  header: ['traceparent', 'x-trace-id', 'x-request-id'],
  query: ['traceId'],
});
```

### Express / Fastify middleware

```typescript
import { traceMiddleware } from 'logixia';

// Zero-config — reads from traceparent / x-trace-id / x-request-id / x-correlation-id
// and generates a UUID v4 if none is present. Sets X-Trace-Id on the response.
app.use(traceMiddleware());

// With custom config:
app.use(
  traceMiddleware({
    enabled: true,
    generator: () => `req_${crypto.randomUUID()}`,
    extractor: {
      header: ['x-trace-id', 'traceparent'],
      query: ['traceId'],
    },
  })
);

// Service layer — no parameters needed, trace ID propagates automatically
class OrderService {
  async createOrder(data: OrderData) {
    await logger.info('Creating order', { items: data.items.length });
    // ^ trace ID is automatically included
    await this.processPayment(data);
  }

  async processPayment(data: OrderData) {
    await logger.info('Processing payment', { amount: data.total });
    // ^ same trace ID, propagated automatically through await
  }
}
```

The default headers checked for an incoming trace ID (in priority order) are: `traceparent`, `x-trace-id`, `x-request-id`, `x-correlation-id`, `trace-id`.

### NestJS trace middleware

The `TraceMiddleware` class integrates directly with NestJS's middleware system. `LogixiaLoggerModule.forRoot()` applies it automatically across all routes — no manual wiring needed:

```typescript
// Applied automatically by LogixiaLoggerModule.forRoot().
// For manual use in a custom module:

import { MiddlewareConsumer, Module, NestModule } from '@nestjs/common';
import { TraceMiddleware } from 'logixia';

@Module({})
export class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer) {
    consumer.apply(TraceMiddleware).forRoutes('*');
  }
}
```

### Kafka trace interceptor

Propagates trace IDs through Kafka message handlers. Reads `traceId` / `trace_id` / `x-trace-id` from the message body or headers and runs the handler inside that trace context:

```typescript
import { KafkaTraceInterceptor } from 'logixia';
import { UseInterceptors, Controller } from '@nestjs/common';
import { MessagePattern } from '@nestjs/microservices';

@Controller()
@UseInterceptors(KafkaTraceInterceptor)
export class OrdersConsumer {
  @MessagePattern('order.created')
  async handle(data: OrderCreatedEvent) {
    // getCurrentTraceId() works here — extracted from the Kafka message
    await logger.info('Processing order event', { orderId: data.orderId });
  }
}
```

`KafkaTraceInterceptor` and `WebSocketTraceInterceptor` are automatically provided when you use `LogixiaLoggerModule.forRoot()`. You can also inject them directly.

### WebSocket trace interceptor

Propagates trace IDs through WebSocket event handlers. Reads `traceId` from the message body, event payload, or handshake query:

```typescript
import { WebSocketTraceInterceptor } from 'logixia';
import { UseInterceptors, WebSocketGateway, SubscribeMessage } from '@nestjs/websockets';

@WebSocketGateway()
@UseInterceptors(WebSocketTraceInterceptor)
export class EventsGateway {
  @SubscribeMessage('message')
  async handleMessage(client: Socket, data: MessagePayload) {
    // trace ID propagated from the WebSocket event context
    await logger.info('WS message received', { event: 'message' });
  }
}
```

---

## NestJS integration

Drop-in module with zero boilerplate. Registers `TraceMiddleware` for all routes, provides `LogixiaLoggerService`, `KafkaTraceInterceptor`, and `WebSocketTraceInterceptor` via the global DI container.

```typescript
// app.module.ts
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'nestjs-api',
      environment: process.env.NODE_ENV ?? 'development',
      traceId: true,
      transports: {
        console: {},
        file: { filename: 'app.log', dirname: './logs', maxSize: '50MB' },
      },
    }),
  ],
})
export class AppModule {}
```

**Async configuration** (for credentials from a config service):

```typescript
LogixiaLoggerModule.forRootAsync({
  imports: [ConfigModule],
  useFactory: async (config: ConfigService) => ({
    appName: 'nestjs-api',
    environment: config.get('NODE_ENV'),
    traceId: true,
    transports: {
      database: {
        type: 'postgresql',
        host: config.get('DB_HOST'),
        database: config.get('DB_NAME'),
        password: config.get('DB_PASSWORD'),
        table: 'logs',
      },
    },
  }),
  inject: [ConfigService],
});
```

**Inject the logger** in any service or controller. Since `LogixiaLoggerModule` is globally scoped, no per-module import is needed:

```typescript
// orders.service.ts
import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService } from 'logixia';

@Injectable()
export class OrdersService {
  constructor(private readonly logger: LogixiaLoggerService) {}

  async createOrder(dto: CreateOrderDto) {
    await this.logger.info('Creating order', { userId: dto.userId });
    // ...
  }
}
```

**Feature-scoped child logger** — create a logger pre-scoped to a specific context string:

```typescript
// orders.module.ts
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia';
import { OrdersService } from './orders.service';

@Module({
  imports: [LogixiaLoggerModule.forFeature('OrdersModule')],
  providers: [OrdersService],
})
export class OrdersModule {}
```

```typescript
// orders.service.ts — inject the feature-scoped token
import { Inject, Injectable } from '@nestjs/common';
import { LOGIXIA_LOGGER_PREFIX, LogixiaLoggerService } from 'logixia';

@Injectable()
export class OrdersService {
  constructor(
    @Inject(`${LOGIXIA_LOGGER_PREFIX}ORDERSMODULE`)
    private readonly logger: LogixiaLoggerService
  ) {}
}
```

`LogixiaLoggerService` exposes the full `LogixiaLogger` API: `info`, `warn`, `error`, `debug`, `trace`, `verbose`, `logLevel`, `time`, `timeEnd`, `timeAsync`, `setLevel`, `getLevel`, `setContext`, `child`, `close`, `getCurrentTraceId`, and more.

### @LogMethod decorator

Automatically logs method entry, exit, duration, and errors — no manual `try/catch` or `logger.debug` calls needed. Works on both sync and async methods. Reads the `logger` property from the class instance (the NestJS convention).

```typescript
import { Injectable } from '@nestjs/common';
import { LogixiaLoggerService, LogMethod } from 'logixia';

@Injectable()
export class PaymentService {
  constructor(private readonly logger: LogixiaLoggerService) {}

  // Logs entry with args, exit with duration, and errors with full stack trace
  @LogMethod({ level: 'info', logArgs: true, logResult: false })
  async processPayment(orderId: string, amount: number): Promise<void> {
    // your business logic — no try/catch needed for logging
  }

  // Minimal — just tracks duration at debug level
  @LogMethod()
  async fetchExchangeRate(currency: string): Promise<number> {
    return 1.0;
  }
}
```

`@LogMethod` options:

| Option      | Type                             | Default   | Description                                             |
| ----------- | -------------------------------- | --------- | ------------------------------------------------------- |
| `level`     | `'debug' \| 'info' \| 'verbose'` | `'debug'` | Log level for entry / exit messages                     |
| `logArgs`   | `boolean`                        | `true`    | Include method arguments in the entry log               |
| `logResult` | `boolean`                        | `false`   | Include the return value in the exit log                |
| `logErrors` | `boolean`                        | `true`    | Log errors with stack trace when the method throws      |
| `label`     | `string`                         | auto      | Override the auto-detected `ClassName.methodName` label |

### LogixiaExceptionFilter

A global NestJS exception filter that automatically logs unhandled exceptions — HTTP exceptions as `warn`, everything else as `error` — and returns a consistent JSON error shape. Reads the injected `LogixiaLoggerService`; works even without it.

```typescript
// main.ts
import { NestFactory } from '@nestjs/core';
import { LogixiaExceptionFilter } from 'logixia';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalFilters(new LogixiaExceptionFilter());
  await app.listen(3000);
}
bootstrap();
```

With `LogixiaLoggerModule` set up, inject the service directly so it logs to your configured transports:

```typescript
import { APP_FILTER } from '@nestjs/core';
import { LogixiaExceptionFilter, LogixiaLoggerService } from 'logixia';

// In AppModule providers:
{
  provide: APP_FILTER,
  useFactory: (logger: LogixiaLoggerService) => new LogixiaExceptionFilter(logger),
  inject: [LogixiaLoggerService],
}
```

The filter returns this shape on error:

```json
{
  "statusCode": 500,
  "message": "Internal server error",
  "timestamp": "2025-03-14T10:22:01.412Z",
  "path": "/api/orders"
}
```

---

## Correlation ID propagation

`import { ... } from 'logixia/correlation'`

In a microservice architecture each incoming request should carry a `correlationId` that flows through every downstream service call, message queue event, and log line — so you can reconstruct the full request trace in any log aggregator.

logixia ships this as a dedicated `logixia/correlation` sub-package. It uses the same `AsyncLocalStorage` store as the main logger, so every `logger.*` call inside a correlated context automatically includes the ID.

### Correlation Express middleware

```typescript
import { correlationMiddleware } from 'logixia/correlation';

// Zero-config — reads X-Correlation-ID / X-Request-ID from the incoming request.
// Generates a UUID v4 if no header is present.
// Sets X-Correlation-ID on the response.
app.use(correlationMiddleware());

// Custom config:
app.use(
  correlationMiddleware({
    header: 'X-Correlation-ID', // header to read / write. Default: 'X-Correlation-ID'
    generateId: () => crypto.randomUUID(),
    trustIncoming: true, // honour the header from the client. Default: true
    setResponseHeader: true, // echo the ID back in the response. Default: true
  })
);
```

### Correlation Fastify hook

```typescript
import Fastify from 'fastify';
import { correlationFastifyHook } from 'logixia/correlation';

const app = Fastify();
app.addHook('onRequest', correlationFastifyHook());
```

### Outbound fetch / axios

Every outbound HTTP call made inside a correlated context automatically carries the `X-Correlation-ID` header.

**fetch:**

```typescript
import { correlationFetch } from 'logixia/correlation';

// Drop-in replacement for global fetch — forwards the active correlation ID automatically
const res = await correlationFetch('https://inventory-service/api/items', {
  method: 'GET',
  headers: { Authorization: `Bearer ${token}` },
});
```

**axios:**

```typescript
import axios from 'axios';
import { createCorrelationAxiosInterceptor } from 'logixia/correlation';

const client = axios.create({ baseURL: 'https://inventory-service' });
createCorrelationAxiosInterceptor(client); // attaches X-Correlation-ID to every request
```

### Kafka / SQS helpers

```typescript
import {
  buildKafkaCorrelationHeaders, // → { 'X-Correlation-ID': '...', 'X-Request-ID': '...' }
  extractMessageCorrelationId, // read correlationId from a Kafka/SQS message body
  childFromRequest, // create a child logger pre-seeded with request context
  withCorrelationId, // run a callback inside an explicit correlation context
  getCurrentCorrelationId, // read the active correlation ID (or undefined)
  generateCorrelationId, // generate a new UUID v4 correlation ID
} from 'logixia/correlation';

// Kafka producer — attach correlation headers to every message
const producer = kafka.producer();
await producer.send({
  topic: 'orders',
  messages: [{ value: JSON.stringify(order), headers: buildKafkaCorrelationHeaders() }],
});

// Kafka consumer — restore context for the handler
const correlationId = extractMessageCorrelationId(message.value);
withCorrelationId(correlationId, async () => {
  await orderService.process(message.value);
  // all logger.* calls inside carry correlationId automatically
});

// Create a child logger pre-loaded with request identifiers
const reqLogger = childFromRequest(logger, req);
await reqLogger.info('Order created', { orderId: 'ord_123' });
// → log includes correlationId, requestId, originService
```

**Standalone context (no HTTP framework):**

```typescript
import { withCorrelationId, generateCorrelationId } from 'logixia/correlation';

const id = generateCorrelationId(); // UUID v4

withCorrelationId(id, async () => {
  await processJob(job);
  // all nested logger calls carry id
});
```

---

## Browser support

`import { ... } from 'logixia/browser'`

The `logixia/browser` entry point is a fully tree-shakeable, Node.js-free logger for browsers, Cloudflare Workers, Deno, Bun, and any other non-Node runtime. It has zero imports from `node:fs`, `node:async_hooks`, `node:worker_threads`, or any other Node.js built-in.

```typescript
import { createBrowserLogger } from 'logixia/browser';

const logger = createBrowserLogger({
  appName: 'my-app',
  minLevel: 'info',
  pretty: true, // colorized dev-friendly output via console.group
});

logger.info('App loaded', { route: '/home' });
logger.warn('Feature flag missing', { flag: 'new-checkout' });
logger.error('API call failed', { url: '/api/orders', status: 500 });
```

**Browser console transport** — uses the native `console` API and maps levels to their correct methods (`console.error`, `console.warn`, `console.info`, `console.debug`):

```typescript
import { BrowserLogger, BrowserConsoleTransport } from 'logixia/browser';

const logger = new BrowserLogger({
  appName: 'my-app',
  transports: [new BrowserConsoleTransport({ pretty: true })],
});
```

**Remote batch transport** — buffers log entries and ships them to a remote endpoint in batches. Zero `XMLHttpRequest` or Node.js `http` — uses the global `fetch` API:

```typescript
import { BrowserLogger, BrowserRemoteTransport } from 'logixia/browser';

const logger = new BrowserLogger({
  appName: 'my-app',
  transports: [
    new BrowserRemoteTransport({
      endpoint: 'https://logs.my-company.com/ingest',
      batchSize: 20, // flush when 20 entries accumulate
      flushIntervalMs: 5000, // or every 5 seconds, whichever comes first
      headers: { Authorization: `Bearer ${TOKEN}` },
      minLevel: 'warn', // only ship warn+ to the remote endpoint
    }),
  ],
});
```

The following utilities from the main package are also re-exported from `logixia/browser` (safe for non-Node runtimes):

```typescript
import {
  createTypedLogger, // typed schema-enforced logger factory
  defineLogSchema, // define a compile-time log schema
  createOtelBridge, // OpenTelemetry bridge
  isOtelActive,
  withOtelSpan,
} from 'logixia/browser';
```

---

## Log redaction

Redact sensitive fields before they reach **any** transport — passwords, tokens, PII, credit card numbers. Redaction is applied once before dispatch; no transport can accidentally log sensitive data. The original object is never mutated.

**Path-based redaction** supports dot-notation, `*` (single segment wildcard), and `**` (any-depth wildcard):

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  redact: {
    paths: [
      'password',
      'token',
      'accessToken',
      'refreshToken',
      '*.secret', // any field named 'secret' at one level deep
      'req.headers.*', // all headers
      'user.creditCard', // nested path
      '**.password', // 'password' at any depth
    ],
    censor: '[REDACTED]', // default if omitted
  },
});

await logger.info('User login', {
  username: 'alice',
  password: 'hunter2', // → '[REDACTED]'
  token: 'eyJhbGc...', // → '[REDACTED]'
  user: {
    creditCard: '4111...', // → '[REDACTED]'
    email: 'alice@example.com', // untouched
  },
});
```

**Regex-based redaction** — mask patterns in string values across all fields:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  redact: {
    patterns: [
      /Bearer\s+\S+/gi, // Authorization header values
      /sk-[a-z0-9]{32,}/gi, // OpenAI / Stripe secret keys
      /\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b/g, // credit card numbers
    ],
  },
});
```

Both `paths` and `patterns` can be combined in the same config.

---

## Timer API

Measure the duration of any operation — synchronous or async. The result is logged automatically when the timer ends:

```typescript
// Manual start/stop
logger.time('db-query');
const rows = await db.query('SELECT * FROM orders');
await logger.timeEnd('db-query');
// → logs: Timer 'db-query' finished { duration: '42ms', startTime: '...', endTime: '...' }

// Wrap an async function — timer starts before and stops after, even if the function throws
const result = await logger.timeAsync('process-batch', async () => {
  return await processBatch(items);
});
```

`timeEnd` returns the duration in milliseconds so you can use it in your own logic:

```typescript
const ms = await logger.timeEnd('db-query');
if (ms && ms > 500) {
  await logger.warn('Slow query detected', { durationMs: ms });
}
```

---

## Field management

Control which fields appear in log output at runtime, without changing config:

```typescript
// Disable fields you don't need in a specific context
logger.disableField('traceId');
logger.disableField('appName');

// Re-enable them
logger.enableField('traceId');

// Check whether a field is currently active
const isOn = logger.isFieldEnabled('timestamp'); // true

// Inspect the current state of all fields
const state = logger.getFieldState();
// → { timestamp: true, level: true, appName: false, traceId: false, ... }

// Reset all fields back to the config defaults
logger.resetFieldState();
```

Available field names: `timestamp`, `level`, `appName`, `service`, `traceId`, `message`, `payload`, `timeTaken`, `context`, `requestId`, `userId`, `sessionId`, `environment`.

---

## Transport level control

By default, every transport receives every log entry that passes the global level filter. You can narrow a specific transport to only receive a subset of levels:

```typescript
// Only send errors to the database transport — no noise from info/debug
logger.setTransportLevels('database-0', ['error', 'warn']);

// Check what levels a transport is currently configured for
const levels = logger.getTransportLevels('database-0'); // ['error', 'warn']

// List all registered transport IDs
const ids = logger.getAvailableTransports(); // ['console', 'file-0', 'database-0']

// Remove all level overrides — all transports receive everything again
logger.clearTransportLevelPreferences();
```

---

## Log search

Query your in-memory log history without shipping to Elasticsearch, Datadog, or any external service. Useful in development and lightweight production setups:

```typescript
import { SearchManager } from 'logixia';

const search = new SearchManager({ maxEntries: 10_000 });

// Index a batch of entries (from a file, database query, or any source)
await search.index(logEntries);

// Search by text query, level, and time range
const results = await search.search({
  query: 'payment failed',
  level: 'error',
  from: new Date('2025-01-01'),
  to: new Date(),
  limit: 50,
});
// → sorted by relevance, full metadata included
```

---

## OpenTelemetry

W3C `traceparent` and `tracestate` headers are extracted from incoming requests and attached to every log entry automatically — enabling correlation between distributed traces and log events in Jaeger, Zipkin, Honeycomb, Datadog, and similar tools:

```typescript
const logger = createLogger({
  appName: 'checkout-service',
  environment: 'production',
  traceId: {
    enabled: true,
    extractor: {
      header: ['traceparent', 'tracestate', 'x-trace-id'],
    },
  },
});

// The traceparent header from the incoming request is stored as the trace ID
// and included in every log entry automatically.
app.post('/checkout', async (req, res) => {
  await logger.info('Checkout initiated', { cartId: req.body.cartId });
  // → log carries the W3C traceparent from the request
});
```

---

## Graceful shutdown

Ensures all buffered log entries are flushed to every transport before the process exits. Critical for database and analytics transports that batch writes.

The simplest approach is to set `gracefulShutdown: true` in config — logixia registers SIGTERM and SIGINT handlers automatically:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  gracefulShutdown: true,
  transports: { database: { type: 'postgresql' /* ... */ } },
});
// SIGTERM / SIGINT will flush all transports before exit. No extra code needed.
```

For more control, pass a config object:

```typescript
const logger = createLogger({
  appName: 'api',
  environment: 'production',
  gracefulShutdown: {
    enabled: true,
    timeout: 10_000, // wait up to 10 s; force-exits after
    signals: ['SIGTERM', 'SIGINT', 'SIGHUP'],
  },
  transports: {
    /* ... */
  },
});
```

You can also call `flushOnExit` directly with lifecycle hooks:

```typescript
import { flushOnExit } from 'logixia';

flushOnExit({
  timeout: 5000,
  beforeFlush: async () => {
    // stop accepting new requests
  },
  afterFlush: async () => {
    // any cleanup after all logs are written
  },
});
```

Or flush and close manually — useful in Kubernetes SIGTERM handlers:

```typescript
process.on('SIGTERM', async () => {
  await logger.flush(); // wait for all in-flight writes
  await logger.close(); // close connections, deregister shutdown handlers
  process.exit(0);
});
```

For health monitoring:

```typescript
const { healthy, details } = await logger.healthCheck();
// → { healthy: true, details: { 'database-0': { ready: true, metrics: { logsWritten: 1042, ... } } } }
```

---

## Plugin / extension API

logixia's plugin system lets you hook into every stage of the log lifecycle without touching core logger code. Plugins are plain objects that implement one or more lifecycle methods.

```typescript
import type { LogixiaPlugin, LogEntry } from 'logixia';
```

### Writing a plugin

```typescript
const myPlugin: LogixiaPlugin = {
  name: 'my-plugin',

  // Called once when the logger is constructed (global plugins)
  // or when .use() is called (per-logger plugins).
  onInit() {
    console.log('Plugin initialised');
  },

  // Called for every log entry before it is formatted and written.
  // Return the (optionally mutated) entry to let it through,
  // or return null to silently drop it.
  onLog(entry: LogEntry): LogEntry | null {
    // Example: enrich every entry with a deployment tag
    return { ...entry, data: { ...entry.data, deployId: process.env.DEPLOY_ID } };
  },

  // Called whenever logger.error() receives an Error object.
  onError(error: Error, entry?: LogEntry) {
    // Example: forward to a Sentry-compatible sink
    externalErrorTracker.capture(error, { extra: entry?.data });
  },

  // Called during logger.close() — await-able for graceful teardown.
  async onShutdown() {
    await flushBufferedEvents();
  },
};
```

### Registering plugins globally

Plugins registered on `globalPluginRegistry` are automatically seeded into every logger created after the call.

```typescript
import { usePlugin } from 'logixia';

usePlugin(myPlugin);

// All loggers created from this point forward will run myPlugin.
const logger = createLogger({
  /* ... */
});
```

### Per-logger plugins

Register or remove plugins on a specific logger instance at any time:

```typescript
const logger = createLogger({ context: 'PaymentService' });

// Register
logger.use(myPlugin);

// Deregister by name
logger.unuse('my-plugin');
```

`use()` is chainable:

```typescript
createLogger({ context: 'api' }).use(metricsPlugin).use(auditPlugin).use(samplerPlugin);
```

### Cancelling a log entry

Returning `null` from `onLog` drops the entry before it reaches any transport — useful for sampling, deduplication, or environment-based suppression:

```typescript
const devOnlyPlugin: LogixiaPlugin = {
  name: 'dev-only',
  onLog(entry) {
    // Suppress debug/trace entries in production
    if (process.env.NODE_ENV === 'production' && entry.level <= 20) {
      return null; // drop it
    }
    return entry;
  },
};
```

Multiple `onLog` hooks run in registration order. If any hook returns `null` the pipeline stops and no further hooks are called.

---

## Metrics → Prometheus

`MetricsPlugin` converts log events into Prometheus-compatible counters, histograms, and gauges — no separate instrumentation library required. The `/metrics` endpoint serves the standard Prometheus text exposition format.

```typescript
import { createMetricsPlugin } from 'logixia';
```

### Quick start (counters)

```typescript
import { createLogger, createMetricsPlugin } from 'logixia';
import http from 'node:http';

const metrics = createMetricsPlugin({
  http_requests_total: {
    type: 'counter',
    help: 'Total HTTP requests processed',
    // Which log fields become Prometheus labels
    labels: ['method', 'status', 'route'],
  },
  auth_failures_total: {
    type: 'counter',
    help: 'Authentication failures',
    labels: ['reason'],
  },
});

const logger = createLogger({ context: 'api' }).use(metrics);

// Every log entry automatically increments the matching counter
await logger.info('request handled', { method: 'GET', status: 200, route: '/users' });
await logger.warn('auth failed', { reason: 'bad-token' });

// Expose /metrics
http.createServer(metrics.httpHandler()).listen(9100);
```

The `/metrics` response looks like:

```
# HELP logixia_http_requests_total Total HTTP requests processed
# TYPE logixia_http_requests_total counter
logixia_http_requests_total{method="GET",status="200",route="/users"} 1

# HELP logixia_auth_failures_total Authentication failures
# TYPE logixia_auth_failures_total counter
logixia_auth_failures_total{reason="bad-token"} 1
```

### Histograms

Histograms record the distribution of a numeric field extracted from log entries. Typical use: request latency in milliseconds.

```typescript
const metrics = createMetricsPlugin({
  http_request_duration_ms: {
    type: 'histogram',
    help: 'HTTP request latency in milliseconds',
    // The log field whose numeric value is recorded as the observation
    valueField: 'durationMs',
    labels: ['route', 'method'],
    // Custom bucket boundaries (defaults: [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000])
    buckets: [10, 50, 100, 200, 500, 1000, 5000],
  },
});

await logger.info('request complete', { route: '/api/orders', method: 'POST', durationMs: 142 });
```

Prometheus output includes `_bucket`, `_sum`, and `_count` lines, compatible with `histogram_quantile()`:

```
# HELP logixia_http_request_duration_ms HTTP request latency in milliseconds
# TYPE logixia_http_request_duration_ms histogram
logixia_http_request_duration_ms_bucket{le="10",route="/api/orders",method="POST"} 0
logixia_http_request_duration_ms_bucket{le="50",route="/api/orders",method="POST"} 0
logixia_http_request_duration_ms_bucket{le="100",route="/api/orders",method="POST"} 0
logixia_http_request_duration_ms_bucket{le="200",route="/api/orders",method="POST"} 1
...
logixia_http_request_duration_ms_bucket{le="+Inf",route="/api/orders",method="POST"} 1
logixia_http_request_duration_ms_sum{route="/api/orders",method="POST"} 142
logixia_http_request_duration_ms_count{route="/api/orders",method="POST"} 1
```

### Gauges

Gauges track the current value of a numeric field — useful for queue depths, active connections, cache sizes:

```typescript
const metrics = createMetricsPlugin({
  queue_depth: {
    type: 'gauge',
    help: 'Current number of items in the processing queue',
    valueField: 'depth',
    labels: ['queue'],
  },
});

await logger.info('queue snapshot', { queue: 'email', depth: 47 });
```

### Exposing the /metrics endpoint

**Plain Node.js `http` module:**

```typescript
import http from 'node:http';

http.createServer(metrics.httpHandler()).listen(9100);
// GET http://localhost:9100/ → Prometheus text format
```

**Express:**

```typescript
import express from 'express';

const app = express();
app.get('/metrics', metrics.expressHandler());
app.listen(3000);
```

**Manual render (any framework):**

```typescript
// Returns the full Prometheus text string
const text = metrics.render();
res.setHeader('Content-Type', 'text/plain; version=0.0.4; charset=utf-8');
res.end(text);
```

**Reset all counters** (e.g., between tests):

```typescript
metrics.reset();
```

### Metric configuration reference

```typescript
interface CounterConfig {
  type: 'counter';
  help?: string; // # HELP line in Prometheus output
  labels?: string[]; // Log entry fields to use as label keys
}

interface HistogramConfig {
  type: 'histogram';
  help?: string;
  valueField: string; // The log field holding the numeric observation
  labels?: string[];
  buckets?: number[]; // Upper-inclusive bucket boundaries (ms or any unit)
}

interface GaugeConfig {
  type: 'gauge';
  help?: string;
  valueField: string; // The log field whose value sets the gauge
  labels?: string[];
}

// Map of Prometheus metric name → config
type MetricsMap = Record<string, CounterConfig | HistogramConfig | GaugeConfig>;
```

All metric names are automatically prefixed with `logixia_` in the output. If a histogram or gauge entry is missing the `valueField`, the entry is still counted but no numeric observation is recorded.

---

## Logger instance API

Complete reference for every method available on a logger instance returned by `createLogger` or `LogixiaLoggerService`:

```typescript
// Log methods
await logger.error(message: string | Error, data?: Record<string, unknown>): Promise<void>
await logger.warn(message: string, data?: Record<string, unknown>): Promise<void>
await logger.info(message: string, data?: Record<string, unknown>): Promise<void>
await logger.debug(message: string, data?: Record<string, unknown>): Promise<void>
await logger.trace(message: string, data?: Record<string, unknown>): Promise<void>
await logger.verbose(message: string, data?: Record<string, unknown>): Promise<void>
await logger.logLevel(level: string, message: string, data?): Promise<void>  // dynamic dispatch

// Timer API
logger.time(label: string): void
await logger.timeEnd(label: string): Promise<number | undefined>          // returns ms
await logger.timeAsync<T>(label: string, fn: () => Promise<T>): Promise<T>

// Level management
logger.setLevel(level: string): void
logger.getLevel(): string

// Context management
logger.setContext(context: string): void
logger.getContext(): string | undefined
logger.child(context: string, data?: Record<string, unknown>): ILogger

// Field management
logger.enableField(fieldName: string): void
logger.disableField(fieldName: string): void
logger.isFieldEnabled(fieldName: string): boolean
logger.getFieldState(): Record<string, boolean>
logger.resetFieldState(): void

// Transport management
logger.getAvailableTransports(): string[]
logger.setTransportLevels(transportId: string, levels: string[]): void
logger.getTransportLevels(transportId: string): string[] | undefined
logger.clearTransportLevelPreferences(): void

// Plugin API
logger.use(plugin: LogixiaPlugin): this         // register a plugin; chainable
logger.unuse(pluginName: string): this          // remove a plugin by name; chainable

// Lifecycle
await logger.flush(): Promise<void>
await logger.close(): Promise<void>
await logger.healthCheck(): Promise<{ healthy: boolean; details: Record<string, unknown> }>
```

**Utility exports** available at the top level:

```typescript
import {
  generateTraceId, // () => string — UUID v4
  getCurrentTraceId, // () => string | undefined
  runWithTraceId, // (id, fn, data?) => T
  setTraceId, // (id, data?) => void
  extractTraceId, // (req, config) => string | undefined
  isError, // (value) => value is Error
  normalizeError, // (value) => Error
  serializeError, // (error, options?) => Record<string, unknown>
  applyRedaction, // (payload, config) => payload
  flushOnExit, // (options?) => void
  registerForShutdown, // (logger) => void
  deregisterFromShutdown, // (logger) => void
  resetShutdownHandlers, // () => void — useful in tests
  // NestJS extras
  InjectLogger, // @InjectLogger() parameter decorator
  LogMethod, // @LogMethod() method decorator
  LogixiaExceptionFilter, // global exception filter
} from 'logixia';

// Cloud transports (import directly):
import { CloudWatchTransport } from 'logixia';
import { GCPTransport } from 'logixia';
import { AzureMonitorTransport } from 'logixia';

// Plugin API:
import type { LogixiaPlugin } from 'logixia';
import { globalPluginRegistry, PluginRegistry, usePlugin } from 'logixia';

// Metrics → Prometheus:
import type {
  CounterConfig,
  GaugeConfig,
  HistogramConfig,
  MetricConfig,
  MetricsMap,
} from 'logixia';
import { createMetricsPlugin, MetricsPlugin } from 'logixia';

// Correlation ID sub-package:
import { correlationMiddleware, correlationFetch, withCorrelationId } from 'logixia/correlation';

// Browser / Edge sub-package:
import {
  createBrowserLogger,
  BrowserConsoleTransport,
  BrowserRemoteTransport,
} from 'logixia/browser';
```

---

## CLI tool

logixia ships a CLI for working with log files directly. After installing, the `logixia` command is available via `npx` or globally:

```bash
npx logixia --help
```

Seven subcommands are available:

| Command   | One-line summary                                             |
| --------- | ------------------------------------------------------------ |
| `tail`    | Stream a log file in real-time with level highlighting       |
| `search`  | Full-text or field-specific search with table / JSON output  |
| `stats`   | Level counts and time distribution summary                   |
| `analyze` | Pattern recognition and anomaly detection                    |
| `export`  | Convert between NDJSON, JSON, and CSV                        |
| `query`   | SQL-like queries with aggregations, sorting, and live follow |
| `explore` | Full-screen interactive TUI browser with search and export   |

**`tail`** — stream a log file in real-time, with optional filtering and level highlighting:

```bash
# Show last 10 lines
npx logixia tail ./logs/app.log

# Follow and filter by level
npx logixia tail ./logs/app.log --follow --filter level:error

# Filter by a specific field value
npx logixia tail ./logs/app.log --follow --filter user_id:usr_123

# Color output by log level
npx logixia tail ./logs/app.log --highlight level
```

**`search`** — query a log file with field-specific or full-text search:

```bash
# Full-text search
npx logixia search ./logs/app.log --query "payment failed"

# Field-specific search
npx logixia search ./logs/app.log --query "level:error"
npx logixia search ./logs/app.log --query "user_id:usr_123"

# Output as JSON or table
npx logixia search ./logs/app.log --query "timeout" --format json
npx logixia search ./logs/app.log --query "timeout" --format table
```

**`stats`** — summarize a log file with counts by level and time distribution:

```bash
npx logixia stats ./logs/app.log
```

**`analyze`** — run pattern recognition and anomaly detection across a log file:

```bash
npx logixia analyze ./logs/app.log
```

**`export`** — convert a log file between formats (JSON, CSV, text):

```bash
npx logixia export ./logs/app.log --format csv --output ./logs/app.csv
```

**`query`** — run SQL-like queries over NDJSON / JSON log files directly in your terminal:

```bash
# Basic filter
npx logixia query ./logs/app.log --sql "SELECT * FROM logs WHERE level='error'"

# Multiple conditions
npx logixia query ./logs/app.log --sql "WHERE level='error' AND duration > 500"

# Select specific fields
npx logixia query ./logs/app.log --sql "SELECT level, message, duration FROM logs WHERE level='warn'"

# Time-range shortcuts
npx logixia query ./logs/app.log --since "last 2 hours"
npx logixia query ./logs/app.log --since "last 30 minutes" --until "last 5 minutes"
npx logixia query ./logs/app.log --since today
npx logixia query ./logs/app.log --since yesterday

# Aggregations
npx logixia query ./logs/app.log --sql "COUNT BY level"
npx logixia query ./logs/app.log --sql "GROUP BY statusCode"
npx logixia query ./logs/app.log --sql "AVG(duration) BY endpoint"
npx logixia query ./logs/app.log --sql "SUM(duration) BY service"

# Sorting and limiting
npx logixia query ./logs/app.log --sql "WHERE level='error' ORDER BY timestamp DESC LIMIT 20"
npx logixia query ./logs/app.log --order-by duration --limit 10

# Output formats
npx logixia query ./logs/app.log --sql "COUNT BY level" --format table
npx logixia query ./logs/app.log --sql "WHERE level='error'" --format json

# Live tail with a SQL filter — streams new entries as they are written
npx logixia query ./logs/app.log --follow --sql "WHERE level='error'"
npx logixia query ./logs/app.log --follow --since "last 1 hour" --sql "WHERE duration > 1000"
```

Supported SQL features:

| Clause / keyword             | Example                                  |
| ---------------------------- | ---------------------------------------- |
| `SELECT fields`              | `SELECT level, message, duration`        |
| `WHERE` conditions           | `WHERE level='error' AND duration > 500` |
| Comparison ops               | `=  !=  >  >=  <  <=`                    |
| `LIKE` / `NOT LIKE`          | `WHERE message LIKE '%timeout%'`         |
| `IN` / `NOT IN`              | `WHERE level IN ('error', 'warn')`       |
| `COUNT BY field`             | `COUNT BY statusCode`                    |
| `GROUP BY field`             | `GROUP BY endpoint`                      |
| `AVG(f) BY g`                | `AVG(duration) BY endpoint`              |
| `SUM / MIN / MAX(f) BY g`    | `MAX(duration) BY service`               |
| `ORDER BY field [ASC\|DESC]` | `ORDER BY timestamp DESC`                |
| `LIMIT n`                    | `LIMIT 50`                               |

`--since` / `--until` accept: `"last N minutes"`, `"last N hours"`, `"last N days"`, `"today"`, `"yesterday"`, or any ISO 8601 date string.

### explore — Visual TUI log explorer

`logixia explore` opens a full-screen interactive terminal UI built on raw ANSI + chalk — no extra runtime dependencies required.

```bash
# Open a log file in the TUI
npx logixia explore ./logs/app.log

# Start with only error and warn entries visible
npx logixia explore ./logs/app.log --levels error,warn

# Pre-populate the search field
npx logixia explore ./logs/app.log --search "payment"

# Follow mode: append new entries as the file grows
npx logixia explore ./logs/app.log --follow
```

**Options:**

| Flag               | Default | Description                                                           |
| ------------------ | ------- | --------------------------------------------------------------------- |
| `--follow`         | off     | Tail the file; append new entries as they are written                 |
| `--levels <list>`  | all     | Comma-separated levels to show: `error,warn,info,debug,trace,verbose` |
| `--search <query>` | —       | Pre-populate the search field on open                                 |

**Layout:**

```
┌────────────────────────────────────────────────────────────────────────────┐
│ LOGIXIA EXPLORE  app.log  [42/127]  /payment                               │
│  E  W  I  D  T  V                                    /: search             │
│  TIME           LVL  MESSAGE                                               │
│ 08:00:01.042   ERR  Request failed   status=500 user=abc                   │
│▶08:00:02.117   INF  Request completed  status=200 user=def    ← selected   │
│ 08:00:03.890   WRN  Slow query detected  duration=1240                     │
│──────────────────────────────────────────────────────────────── ▼ DETAIL ─│
│  {                                                                         │
│    "timestamp": "...",                                                     │
│    "level": "info",                                                        │
│    "message": "Request completed",                                         │
│    "status": 200,                                                          │
│    "user": "def"                                                           │
│  }                                                                         │
│  j/k move  /search  x export  E/W/I/D/T/V filter  J/K detail↕  q quit    │
└────────────────────────────────────────────────────────────────────────────┘
```

**Keyboard shortcuts:**

| Key             | Action                                                                         |
| --------------- | ------------------------------------------------------------------------------ |
| `j` / `↓`       | Move selection down                                                            |
| `k` / `↑`       | Move selection up                                                              |
| `g` / `Home`    | Jump to first entry                                                            |
| `G` / `End`     | Jump to last entry                                                             |
| `PgUp` / `PgDn` | Page up / page down                                                            |
| `J` / `K`       | Scroll detail panel down / up                                                  |
| `/`             | Enter search mode (type query → `Enter` to confirm, `Esc` to clear)            |
| `E W I D T V`   | Toggle error / warn / info / debug / trace / verbose filter                    |
| `f`             | Toggle real-time follow mode                                                   |
| `x`             | Export filtered entries (enter a path ending in `.json`, `.csv`, or `.ndjson`) |
| `q` / `Ctrl+C`  | Quit and return to terminal                                                    |

**Detail panel** shows syntax-highlighted JSON of the selected entry. For error entries with a `stack` field, the full stack trace is rendered below the JSON with frame locations highlighted.

**Export** supports three formats determined by the file extension you type:

- `.json` — pretty-printed JSON array
- `.csv` — comma-separated with auto-detected column headers
- `.ndjson` / `.jsonl` — newline-delimited JSON (one entry per line)

The explorer works in any TTY-capable terminal (macOS Terminal, iTerm2, Windows Terminal, VS Code integrated terminal) and degrades gracefully in non-TTY environments (useful when piping to other commands).

---

## Configuration reference

```typescript
interface LoggerConfig {
  // Required
  appName: string;
  environment: 'development' | 'production';

  // Output format (applies to console and file text output)
  format?: {
    timestamp?: boolean; // include ISO timestamp. Default: true
    colorize?: boolean; // ANSI color output. Default: true
    json?: boolean; // JSON lines output. Default: false
  };

  // Trace ID — true enables UUID v4 auto-generation; pass an object for custom config
  traceId?:
    | boolean
    | {
        enabled: boolean;
        generator?: () => string; // custom ID generator
        contextKey?: string;
        extractor?: {
          header?: string | string[]; // headers to check
          query?: string | string[]; // query params to check
          body?: string | string[]; // body fields to check
          params?: string | string[]; // route params to check
        };
      };

  // Suppress all output. Useful in test environments
  silent?: boolean;

  // Level configuration
  levelOptions?: {
    level?: 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'verbose' | string;
    levels?: Record<string, number>; // custom level priority map
    colors?: Record<string, LogColor>; // color per level
  };

  // Visible fields in text output
  fields?: Partial<
    Record<
      | 'timestamp'
      | 'level'
      | 'appName'
      | 'service'
      | 'traceId'
      | 'message'
      | 'payload'
      | 'timeTaken'
      | 'context'
      | 'requestId'
      | 'userId'
      | 'sessionId'
      | 'environment',
      string | boolean
    >
  >;

  // Field redaction — applied before any transport receives the entry
  redact?: {
    paths?: string[]; // dot-notation paths; supports * and ** wildcards
    patterns?: RegExp[]; // regex patterns applied to string values
    censor?: string; // replacement string. Default: '[REDACTED]'
  };

  // Per-namespace log level overrides; keys are patterns, values are levels
  namespaceLevels?: Record<string, string>;

  // Graceful shutdown — true for defaults, or a config object for full control
  gracefulShutdown?:
    | boolean
    | {
        enabled: boolean;
        timeout?: number; // ms to wait before force-exit. Default: 5000
        signals?: NodeJS.Signals[]; // Default: ['SIGTERM', 'SIGINT']
      };

  // Transports — all optional, all concurrent
  transports?: {
    console?: {
      level?: string;
      colorize?: boolean;
      timestamp?: boolean;
      format?: 'json' | 'text';
    };

    file?:
      | {
          filename: string;
          dirname?: string;
          maxSize?: string | number; // e.g. '50MB', '1GB', or bytes
          maxFiles?: number;
          datePattern?: string; // e.g. 'YYYY-MM-DD'
          zippedArchive?: boolean;
          format?: 'json' | 'text' | 'csv';
          level?: string;
          batchSize?: number;
          flushInterval?: number; // ms
          rotation?: {
            interval?: '1h' | '6h' | '12h' | '1d' | '1w' | '1m' | '1y';
            maxSize?: string | number;
            maxFiles?: number;
            compress?: boolean;
          };
        }
      | Array<FileTransportConfig>; // array for multiple file targets

    database?:
      | {
          type: 'postgresql' | 'mysql' | 'mongodb' | 'sqlite';
          host?: string;
          port?: number;
          database: string;
          table?: string; // SQL databases
          collection?: string; // MongoDB
          connectionString?: string; // MongoDB connection string
          username?: string;
          password?: string;
          ssl?: boolean;
          batchSize?: number;
          flushInterval?: number; // ms
        }
      | Array<DatabaseTransportConfig>;

    analytics?: {
      datadog?: {
        apiKey: string;
        site?: 'datadoghq.com' | 'datadoghq.eu' | 'us3.datadoghq.com' | 'us5.datadoghq.com';
        service?: string;
        version?: string;
        env?: string;
        enableMetrics?: boolean;
        enableLogs?: boolean;
        enableTraces?: boolean;
      };
      mixpanel?: {
        token: string;
        distinct_id?: string;
        enableSuperProperties?: boolean;
        superProperties?: Record<string, unknown>;
      };
      segment?: {
        writeKey: string;
        dataPlaneUrl?: string;
        enableBatching?: boolean;
        flushAt?: number;
        flushInterval?: number;
      };
      googleAnalytics?: {
        measurementId: string;
        apiSecret: string;
        clientId?: string;
        enableEcommerce?: boolean;
      };
    };

    custom?: ITransport[]; // any object implementing { name, write, close? }
  };
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
