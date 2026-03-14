# 04 — Missing & Incomplete Features

> These are features that are either stubbed out, architecturally missing,
> or promised in the README but not actually implemented.

---

## FEAT-01 🟠 File Compression — stub only, never called

**File:** `src/transports/file.transport.ts`
**Current state:**

```typescript
private async compressFile(filePath: string): Promise<void> {
  // TODO: implement gzip compression
  console.log(`Compressing ${filePath}`);  // ← does nothing
}
```

The README and API docs mention compression. It's called in the rotation flow but produces no output.

### Implementation

```typescript
import { createReadStream, createWriteStream } from 'node:fs';
import { rename, unlink } from 'node:fs/promises';
import { createGzip } from 'node:zlib';
import { pipeline } from 'node:stream/promises';

private async compressFile(filePath: string): Promise<void> {
  const gzippedPath = `${filePath}.gz`;

  await pipeline(
    createReadStream(filePath),
    createGzip(),
    createWriteStream(gzippedPath),
  );

  // Only remove original after gz is confirmed written
  await unlink(filePath);
}
```

Update `FileTransportConfig` to add:

```typescript
interface FileTransportConfig {
  compress?: boolean; // default: false
  compressionFormat?: 'gzip'; // extensible for future brotli support
}
```

And only call `compressFile()` when `config.compress === true` after rotation.

---

## FEAT-02 🟡 Real NLP Search — currently just regex pattern matching

**File:** `src/search/engines/nlp-search-engine.ts`
**Current state:** Uses `String.prototype.match()` with hard-coded regex patterns
to "detect intent". This is not NLP — it's keyword spotting.

### Short-term fix (v1.2 — no external dependency)

Build a proper **token-based query language** parser (similar to GitHub's search):

```
level:error service:payments after:2024-01-01 "database connection"
traceId:abc123 user:42
```

```typescript
// Proper query parser — no regex NLP, but honest and useful
function parseQueryTokens(query: string): ParsedNLQuery {
  const tokens = tokenize(query);
  const filters: SearchFilters = {};
  const freeText: string[] = [];

  for (const token of tokens) {
    if (token.key === 'level')
      filters.levels = [...(filters.levels ?? []), token.value as LogLevelString];
    else if (token.key === 'service') filters.service = token.value;
    else if (token.key === 'traceId') filters.traceId = token.value;
    else if (token.key === 'user') filters.userId = token.value;
    else if (token.key === 'after')
      filters.timeRange = { ...filters.timeRange, start: new Date(token.value) };
    else if (token.key === 'before')
      filters.timeRange = { ...filters.timeRange, end: new Date(token.value) };
    else freeText.push(token.raw);
  }

  return { filters, freeText: freeText.join(' '), intent: 'search', confidence: 1 };
}
```

### Long-term fix (v2.0 — opt-in external dep)

Add an optional `openai` or `@anthropic-ai/sdk` peer dependency for true semantic
search via embeddings:

```typescript
// config
const logger = createLogger({
  search: {
    nlp: {
      provider: 'openai',
      apiKey: process.env.OPENAI_API_KEY,
      model: 'text-embedding-3-small',
    },
  },
});
```

Mark clearly in docs: "Basic NLP is built-in. Semantic search requires an optional
AI provider configuration."

---

## FEAT-03 🟡 Prometheus Metrics Export

Many observability pipelines (Grafana, k8s, Datadog agent) scrape `/metrics` in
Prometheus format. Logixia already collects internal metrics (write counts, error
rates, avg duration per transport) — they just aren't exposed.

### Design

```typescript
// New file: src/exporters/prometheus.exporter.ts

export class PrometheusExporter {
  constructor(private manager: TransportManager) {}

  /**
   * Returns Prometheus text format metrics string.
   * Plug into your HTTP server: res.end(exporter.getMetrics())
   */
  getMetrics(): string {
    const metrics = this.manager.getMetrics();
    const lines: string[] = [];

    for (const [transportId, m] of Object.entries(metrics)) {
      lines.push(
        `# HELP logixia_transport_writes_total Total writes by transport`,
        `# TYPE logixia_transport_writes_total counter`,
        `logixia_transport_writes_total{transport="${transportId}"} ${m.totalWrites}`,

        `# HELP logixia_transport_errors_total Total errors by transport`,
        `# TYPE logixia_transport_errors_total counter`,
        `logixia_transport_errors_total{transport="${transportId}"} ${m.totalErrors}`,

        `# HELP logixia_transport_write_duration_ms Average write duration`,
        `# TYPE logixia_transport_write_duration_ms gauge`,
        `logixia_transport_write_duration_ms{transport="${transportId}"} ${m.avgDurationMs}`
      );
    }

    return lines.join('\n') + '\n';
  }
}
```

Export it from `src/index.ts` and document in README under "Observability".

---

## FEAT-04 🟡 Log Sampling for High-Volume Scenarios

When logging millions of events per minute, you may want to capture only a percentage:

```typescript
interface LoggerConfig<TLevels> {
  sampling?: {
    rate: number; // 0.0 – 1.0 (1.0 = keep all)
    levels?: Partial<Record<LogLevelString, number>>; // per-level override
  };
}

// Example: sample 10 % of debug, keep 100 % of errors
createLogger({
  sampling: {
    rate: 1.0,
    levels: {
      debug: 0.1,
      trace: 0.01,
    },
  },
});
```

Implementation in `LogixiaLogger.log()`:

```typescript
private shouldSample(level: string): boolean {
  const rate = this.config.sampling?.levels?.[level]
    ?? this.config.sampling?.rate
    ?? 1.0;
  return Math.random() < rate;
}
```

---

## FEAT-05 🟡 Config File Support (`logixia.config.json` / `.logixiarc`)

Users want to configure logixia from a file without modifying application code.
This is especially useful for the CLI tool:

```json
// logixia.config.json
{
  "appName": "my-app",
  "level": "info",
  "transports": [
    { "type": "console", "format": "json" },
    { "type": "file", "filename": "logs/app.log", "rotate": "1d" }
  ]
}
```

```typescript
// src/config/config-loader.ts
import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const CONFIG_FILES = ['logixia.config.json', '.logixiarc', '.logixiarc.json'];

export function loadConfigFile(cwd = process.cwd()): Partial<LoggerConfig> | null {
  for (const name of CONFIG_FILES) {
    const path = join(cwd, name);
    if (existsSync(path)) {
      const raw = JSON.parse(readFileSync(path, 'utf-8'));
      return validateConfig(raw); // uses zod schema — see 07-dx-and-api.md
    }
  }
  return null;
}
```

---

## FEAT-06 🟡 Environment Variable Overrides

```
LOGIXIA_LEVEL=debug           # override log level
LOGIXIA_APP_NAME=my-service   # override appName
LOGIXIA_FORMAT=json           # override console format
LOGIXIA_FILE_PATH=./logs/app  # override file path
LOGIXIA_DEBUG=1               # enable internal debug output
```

Implementation — merge env vars on top of config at construction time:

```typescript
function applyEnvOverrides(config: LoggerConfig): LoggerConfig {
  return {
    ...config,
    level: (process.env.LOGIXIA_LEVEL ?? config.level) as LogLevelString,
    appName: process.env.LOGIXIA_APP_NAME ?? config.appName,
  };
}
```

---

## FEAT-07 🟢 Express.js Dedicated Module

Currently Express users call `createTraceMiddleware()` manually. A dedicated
`createExpressLogger()` would lower friction:

```typescript
// src/integrations/express.ts
import type { Application } from 'express';

export function setupExpressLogger(app: Application, config?: LoggerConfig): LogixiaLogger {
  const logger = createLogger(config);
  app.use(createTraceMiddleware(config?.traceId));
  app.use(createRequestLogger(logger)); // new: log every req/res
  return logger;
}
```

This mirrors how Pino and Winston work with Express.

---

## FEAT-08 🟢 Async Transport Interface — explicit `flush()` guarantee

Currently `IAsyncTransport.flush()` is optional. In high-throughput code, not having
a flush before process exit drops logs.

```typescript
// Add to IAsyncTransport
interface IAsyncTransport {
  write(entry: LogEntry): Promise<void>;
  flush(): Promise<void>; // REQUIRED, not optional
  close(): Promise<void>; // REQUIRED, not optional
  healthCheck(): Promise<{ healthy: boolean; details?: string }>;
}
```

And add a `process.on('beforeExit', () => logger.flush())` suggestion to the README.

---

## FEAT-09 🟢 OpenTelemetry W3C Trace Context Integration

Like reixo, logixia should natively support W3C `traceparent` headers:

```typescript
// Auto-read traceparent from incoming HTTP request
// Auto-include traceId/spanId in every log entry when inside a traced request
interface TraceIdConfig {
  format?: 'uuid' | 'w3c-traceparent'; // new option
  injectW3CHeaders?: boolean; // inject traceparent on outgoing requests
}
```

This would make logixia a first-class citizen in distributed tracing setups alongside
reixo or any other W3C-compatible library.
