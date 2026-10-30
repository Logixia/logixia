# logixia

<p align="center">
  <img src="https://raw.githubusercontent.com/Logixia/logixia/main/.github/assets/logixia-banner.png" alt="logixia: the async-first TypeScript logger" width="100%"/>
</p>

<p align="center">
  <strong>An async-first TypeScript logger with request tracing, redaction, OpenTelemetry export and the transports you usually have to assemble yourself.</strong>
</p>

<p align="center">
  <a href="https://www.npmjs.com/package/logixia"><img src="https://img.shields.io/npm/v/logixia" alt="npm version"/></a>
  <a href="https://www.npmjs.com/package/logixia"><img src="https://img.shields.io/npm/dm/logixia" alt="npm downloads"/></a>
  <a href="https://github.com/Logixia/logixia/actions/workflows/ci.yml"><img src="https://github.com/Logixia/logixia/actions/workflows/ci.yml/badge.svg" alt="CI"/></a>
  <a href="https://www.npmjs.com/package/logixia"><img src="https://img.shields.io/badge/npm-provenance-brightgreen" alt="npm provenance"/></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/npm/l/logixia" alt="MIT license"/></a>
  <a href="https://www.typescriptlang.org/"><img src="https://img.shields.io/badge/TypeScript-5.0%2B-blue" alt="TypeScript"/></a>
</p>

<p align="center">
  <a href="https://logixia.github.io/logixia/"><strong>Documentation</strong></a> &middot;
  <a href="https://logixia.github.io/logixia/guide/getting-started">Getting started</a> &middot;
  <a href="https://logixia.github.io/logixia/guide/migration-v2">Upgrading to 2.x</a> &middot;
  <a href="https://github.com/Logixia/logixia/issues">Issues</a>
</p>

---

## Why logixia

Most Node loggers give you a fast `info()` and leave the rest to you. logixia keeps the call simple and ships the parts you end up writing anyway:

- **Request tracing built in.** Trace IDs travel through `await` via `AsyncLocalStorage`. Express and Fastify helpers read `traceparent`, `x-request-id` and friends, and every log line inside the request carries the ID.
- **Redaction before dispatch.** Mask paths (`*.password`, `req.headers.authorization`) and regex patterns once, before any transport sees the entry. Transport credentials are also kept out of serialized output and error text.
- **Transports for real destinations.** Console, rotating files, PostgreSQL, MySQL, MongoDB, SQLite, CloudWatch, Google Cloud Logging, Azure Monitor, Datadog, OTLP, Slack, Discord, and a worker-thread wrapper. Several can run on one log call.
- **OpenTelemetry-native.** Read the active span for trace/log correlation, or export logs as OTLP/HTTP records. The OTLP transport builds the JSON itself, so no `@opentelemetry/*` SDK is required to emit logs.
- **Runs outside Node too.** `logixia/browser` has no Node built-ins and is written for browsers and edge runtimes such as Cloudflare Workers.
- **Small footprint.** Three runtime dependencies (`commander`, `fast-json-stringify`, `picocolors`), no install scripts, ESM and CommonJS builds with types.

Log calls are `async` and transport failures are caught internally, so a full disk or a flaky database does not crash your process.

## Install

```bash
npm install logixia
# or: pnpm add logixia | yarn add logixia | bun add logixia
```

**Node.js:** the library declares `node >=16` and is tested in CI on Node 18, 20 and 22. TypeScript 5.0+ is recommended for the bundled types. Building logixia from source needs a newer toolchain (Node `^22.19 || ^24.11 || >=26`); see [CONTRIBUTING.md](./CONTRIBUTING.md).

Database transports use optional drivers that you install yourself: `pg`, `mysql2`, `mongodb`, or `sqlite3` plus `sqlite`.

## Quick start

```typescript
import { createLogger, runWithTraceId } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'development',
  traceId: true,
  redact: { paths: ['password'] },
});

await logger.info('Server started', { port: 3000 });

await runWithTraceId('req-8f3a', async () => {
  await logger.warn('Slow query', { table: 'orders', ms: 842 });
  await logger.info('Login', { user: 'alice', password: 'hunter2' });
});

await logger.error(new Error('Connection timeout'), { orderId: 'ord_123' });
```

Output (colors omitted, stack trace shortened):

```text
[2026-10-30T14:24:30.621Z] [INFO] [api] [ec339fb5-5afb-4675-8c39-ecbad4353818] Server started {"port":3000}
[2026-10-30T14:24:30.623Z] [WARN] [api] [req-8f3a] Slow query {"table":"orders","ms":842}
[2026-10-30T14:24:30.623Z] [INFO] [api] [req-8f3a] Login {"user":"alice","password":"[REDACTED]"}
[2026-10-30T14:24:30.625Z] [ERROR] [api] [ec339fb5-5afb-4675-8c39-ecbad4353818] Connection timeout {"orderId":"ord_123","error":{"name":"Error","message":"Connection timeout","stack":"Error: Connection timeout\n    at main (...)"}}
```

Without a `transports` key logs go to the console. Add `transports` to write to files, databases or cloud services, all concurrently. There is also a ready-made default instance: `import { logger } from 'logixia'`.

→ [Getting started](https://logixia.github.io/logixia/guide/getting-started) · [Configuration](https://logixia.github.io/logixia/guide/configuration) · [Log levels](https://logixia.github.io/logixia/guide/log-levels)

## Feature tour

### Request tracing

```typescript
import { createExpressContextMiddleware, createLogger, getCurrentTraceId } from 'logixia';
import { createExpressMiddleware } from 'logixia/middleware';

const logger = createLogger({ appName: 'api', traceId: true });

app.use(createExpressContextMiddleware({ responseHeader: 'X-Trace-Id' }));
app.use(createExpressMiddleware(logger)); // one request/response log line per call

app.get('/orders', async (_req, res) => {
  await logger.info('Listing orders', { traceId: getCurrentTraceId() });
  res.json([]);
});
```

The trace ID is the first present header of `traceparent` (parsed to its 32-hex trace id), `x-trace-id`, `x-request-id`, `x-correlation-id` or `trace-id`, otherwise a generated UUID. Fastify has `createFastifyContextHook()` and `createFastifyPlugin()`; for anything else, wrap the handler in `runWithTraceId()`. `logixia/correlation` adds `X-Correlation-ID` propagation through `fetch`, axios, Kafka and SQS.

→ [Tracing](https://logixia.github.io/logixia/guide/tracing) · [HTTP logging](https://logixia.github.io/logixia/guide/http-logging) · [Child loggers and context](https://logixia.github.io/logixia/guide/child-loggers-and-context)

### NestJS

Everything NestJS-specific lives in `logixia/nest`, so plain Node apps never load `@nestjs/common`.

```typescript
import { Module } from '@nestjs/common';
import { LogixiaLoggerModule } from 'logixia/nest';

@Module({
  imports: [
    LogixiaLoggerModule.forRoot({
      appName: 'nestjs-api',
      traceId: true,
      transports: { console: {}, file: { filename: 'app.log', dirname: './logs' } },
    }),
  ],
})
export class AppModule {}
```

The module registers the trace middleware, provides `LogixiaLoggerService` for injection and also ships `forRootAsync`, `@LogMethod()`, `LogixiaExceptionFilter`, and Kafka and WebSocket trace interceptors. A full app with Docker Compose is in [`examples/nestjs-app`](./examples/nestjs-app/).

→ [NestJS guide](https://logixia.github.io/logixia/guide/nestjs)

### Redaction

```typescript
const logger = createLogger({
  appName: 'api',
  redact: {
    paths: ['password', '*.token', 'req.headers.authorization', '**.creditCard'],
    patterns: [/Bearer\s+\S+/gi],
    censor: '[REDACTED]',
  },
});

await logger.info('Login', { user: 'alice', password: 'hunter2' });
// → {"user":"alice","password":"[REDACTED]"}
```

Paths support `*` (one segment) and `**` (any depth), match case-insensitively, and the input object is never mutated. Circular references are printed as `[Circular]`.

→ [Redaction](https://logixia.github.io/logixia/guide/redaction)

### Transports

All transports run concurrently. Built-in ones are configured under `transports`; the rest are classes you pass in `transports.custom`.

```typescript
import { createLogger, OtlpLogTransport, SlackTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    console: { level: 'info' },
    file: {
      filename: 'app.log',
      dirname: './logs',
      maxSize: '50MB',
      maxFiles: 14,
      zippedArchive: true,
    },
    custom: [
      new OtlpLogTransport({ url: 'http://localhost:4318/v1/logs', serviceName: 'api' }),
      new SlackTransport({ webhookUrl: process.env.SLACK_WEBHOOK_URL!, level: 'error' }),
    ],
  },
});
```

| Transport                                                                           | Where it comes from                                  | Use it for                                         |
| ----------------------------------------------------------------------------------- | ---------------------------------------------------- | -------------------------------------------------- |
| [Console](https://logixia.github.io/logixia/guide/transports/console)               | `transports.console`                                 | Colorized dev output or JSON to stdout             |
| [File](https://logixia.github.io/logixia/guide/transports/file)                     | `transports.file`                                    | Size/date rotation, gzip, retention                |
| [Database](https://logixia.github.io/logixia/guide/transports/database)             | `transports.database`                                | PostgreSQL, MySQL, MongoDB, SQLite                 |
| [CloudWatch](https://logixia.github.io/logixia/guide/transports/cloudwatch)         | `logixia/cloudwatch`                                 | AWS CloudWatch Logs, optional EMF metrics          |
| [Google Cloud](https://logixia.github.io/logixia/guide/transports/gcp)              | `logixia/gcp`                                        | Cloud Logging with Cloud Trace correlation         |
| [Azure Monitor](https://logixia.github.io/logixia/guide/transports/azure)           | `logixia/azure`                                      | Logs Ingestion API (Data Collection Rule)          |
| [Datadog](https://logixia.github.io/logixia/guide/transports/datadog)               | `transports.analytics.datadog`, `logixia/transports` | Logs and metrics to Datadog                        |
| [OTLP](https://logixia.github.io/logixia/guide/transports/otlp)                     | `logixia`, `logixia/transports`                      | OTLP/HTTP to Grafana, Axiom, SigNoz, a Collector   |
| [Analytics](https://logixia.github.io/logixia/guide/transports/analytics)           | `transports.analytics`                               | Mixpanel, Segment, Google Analytics, Datadog       |
| [Slack / Discord](https://logixia.github.io/logixia/guide/transports/slack-discord) | `logixia`, `logixia/transports`                      | Alerting to a chat channel via webhooks            |
| [Worker thread](https://logixia.github.io/logixia/guide/transports/worker)          | `logixia/worker`                                     | Move file/database/console I/O off the main thread |
| [Custom](https://logixia.github.io/logixia/guide/transports/custom)                 | `transports.custom` with `ITransport`                | Anything else: S3, queues, internal services       |

→ [All transports](https://logixia.github.io/logixia/guide/transports/)

### OpenTelemetry

```typescript
import { createLogger, initOtelBridge } from 'logixia';

initOtelBridge(); // call once, after your OTel SDK starts

const logger = createLogger({ appName: 'checkout' });
await logger.info('Payment processed', { orderId: 'ord_123' });
// the active span's traceId and spanId are added to the entry
```

`initOtelBridge()` uses `@opentelemetry/api` when it is installed and does nothing when it is not. To export logs rather than only correlate them, add `OtlpLogTransport` (see Transports above). Ready-made OTLP configs for Grafana, Axiom, Better Stack and a local Collector are in the [OTLP transport guide](https://logixia.github.io/logixia/guide/transports/otlp).

→ [OpenTelemetry](https://logixia.github.io/logixia/guide/opentelemetry) · [OTLP transport](https://logixia.github.io/logixia/guide/transports/otlp)

### Browser and edge

```typescript
import { createBrowserLogger } from 'logixia/browser';

const logger = createBrowserLogger({ appName: 'web', level: 'info' });
logger.info('Page loaded', { route: '/home' });
```

`logixia/browser` has no Node built-ins and ships a console transport plus a batching `BrowserRemoteTransport` that uses `fetch`. Working examples: [`examples/cloudflare-worker`](./examples/cloudflare-worker/) and [`examples/nextjs`](./examples/nextjs/).

→ [Browser and edge](https://logixia.github.io/logixia/guide/browser-and-edge)

### Sampling and runtime levels

```typescript
const logger = createLogger({
  appName: 'api',
  namespaceLevels: { 'db.*': 'debug', '*': 'info' },
  sampling: {
    rate: 0.1, // keep 10% in steady state
    traceConsistent: true, // keep or drop a whole trace together
    adaptive: { errorRateThreshold: 0.05, boostRate: 1.0, windowMs: 10_000 },
  },
});
```

When the windowed error rate crosses the threshold, the sample rate is raised until things calm down. You can also change levels in a running process: `registerLevelSignal(logger)` cycles the level on `SIGUSR2`, and `createLevelControlHandler(logger)` gives you an HTTP handler to mount behind your own auth.

→ [Sampling](https://logixia.github.io/logixia/guide/sampling) · [Log levels](https://logixia.github.io/logixia/guide/log-levels) · [Graceful shutdown](https://logixia.github.io/logixia/guide/graceful-shutdown)

### Metrics

```typescript
import { createLogger, createMetricsPlugin } from 'logixia';

const metrics = createMetricsPlugin({
  http_requests_total: { type: 'counter', help: 'HTTP requests', labels: ['method', 'status'] },
});
const logger = createLogger({ appName: 'api' }).use(metrics);

await logger.info('request handled', { method: 'GET', status: 200 });
app.get('/metrics', metrics.expressHandler()); // Prometheus text format
```

→ [Metrics](https://logixia.github.io/logixia/guide/metrics)

### CLI and log search

```bash
npx logixia tail ./logs/app.log --follow --filter level:error
npx logixia search ./logs/app.log --query "payment failed"
npx logixia explore ./logs/app.log   # interactive terminal explorer
```

The CLI also has `stats`, `analyze`, `export` and `query`. For in-process search, `logixia/search` exports `SearchManager`, which indexes entries in memory and supports text, filters, natural-language queries and trace correlation.

→ [CLI](https://logixia.github.io/logixia/guide/cli) · [Log search](https://logixia.github.io/logixia/guide/log-search)

### More

Typed fields with `createTypedLogger` and `defineLogSchema` ([typed logger](https://logixia.github.io/logixia/guide/typed-logger)), wide events / canonical log lines with `wideEventMiddleware` and `addEventFields`, a plugin API with `onInit` / `onLog` / `onError` / `onShutdown` hooks, and `createMockLogger` from `logixia/testing` for unit tests ([testing](https://logixia.github.io/logixia/guide/testing)).

## Upgrading from 1.x

2.0 has one breaking change: everything NestJS-specific moved from the root entry to `logixia/nest`.

```diff
- import { LogixiaLoggerModule, LogMethod, InjectLogger } from 'logixia';
+ import { LogixiaLoggerModule, LogMethod, InjectLogger } from 'logixia/nest';
```

The root `logixia` entry no longer loads `@nestjs/common`, so Express, Fastify and plain Node apps work without NestJS installed. → [Migration guide](https://logixia.github.io/logixia/guide/migration-v2)

## Security

- **Redaction** runs before any transport sees an entry, and HTTP logging redacts sensitive headers and query parameters by default.
- **Secrets stay out of output.** Transport credentials (API keys, passwords, webhook URLs, tokens) are hidden from `JSON.stringify`, `util.inspect` and error messages.
- **Supply chain.** Releases are published from CI with [npm provenance](https://docs.npmjs.com/generating-provenance-statements) through npm trusted publishing, so there is no long-lived npm token. The package has no install scripts and three runtime dependencies.
- **Reporting.** Please report vulnerabilities privately through [GitHub private vulnerability reporting](https://github.com/Logixia/logixia/security/advisories/new). See [SECURITY.md](./SECURITY.md).

→ [Security guide](https://logixia.github.io/logixia/guide/security)

## Documentation and examples

| Topic                                                                | Link                                                                         |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| Full documentation                                                   | [logixia.github.io/logixia](https://logixia.github.io/logixia/)              |
| Configuration reference                                              | [guide/configuration](https://logixia.github.io/logixia/guide/configuration) |
| API reference                                                        | [guide/api](https://logixia.github.io/logixia/guide/api)                     |
| Runnable examples (Express, Fastify, Hono, NestJS, Next.js, Workers) | [`examples/`](./examples/)                                                   |
| Changelog                                                            | [CHANGELOG.md](./CHANGELOG.md)                                               |

## Contributing

Pull requests are welcome. For larger changes, open an issue first. Setup, scripts and the commit convention are in [CONTRIBUTING.md](./CONTRIBUTING.md).

```bash
git clone https://github.com/Logixia/logixia.git
cd logixia
npm ci --ignore-scripts
npm test
```

## Sponsor

logixia is free and MIT-licensed, and it is built and maintained by one person. If it saves you time, sponsoring keeps it moving:

- [GitHub Sponsors](https://github.com/sponsors/webcoderspeed)
- [PayPal](https://paypal.me/Sniperspeed)

`npm fund logixia` prints the same links.

## License

[MIT](./LICENSE) © [Sanjeev Sharma](https://github.com/webcoderspeed)
