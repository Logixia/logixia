# 09 — Examples & Documentation

> The README is long but has gaps. The 13 example files have type issues.
> JSDoc is nearly absent. This file covers everything needed to make
> logixia feel polished and production-ready from day one of adoption.

---

## DOCS-01 🟡 Audit of existing 13 example files — known type issues

Run a full typecheck across examples:

```bash
npx tsc --noEmit --strict --skipLibCheck \
  --target ES2020 --module ESNext --moduleResolution node \
  examples/*.ts
```

Fix all errors. The same zero-`any` rule as reixo applies here — examples must
compile cleanly under `--strict` with zero `any`.

### Common patterns to check in each example

1. **Direct `console.log(logger.x)` on a dynamically-added level method** — the
   type must come from `createLogger<'payment' | 'order'>()` generics, not a cast.

2. **Transport config inline objects** — make sure they match the discriminated
   union (e.g. `{ type: 'file', filename: './app.log' }` must satisfy `FileTransportConfig`).

3. **`child()` return type** — must be `LogixiaLogger<TLevels>`, not `any`.

4. **Search engine callbacks** — `SearchResult.log` must be typed as `LogEntry`, not `any`.

### Suggested additions to the example set

| File                       | What it should demonstrate                     |
| -------------------------- | ---------------------------------------------- |
| `14-prometheus-metrics.ts` | `PrometheusExporter.getMetrics()` with Express |
| `15-env-var-config.ts`     | `urlEnvVar`, `apiKeyEnvVar` patterns           |
| `16-log-sampling.ts`       | `sampling.rate` for high-volume scenarios      |
| `17-opentelemetry-w3c.ts`  | W3C traceparent integration                    |
| `18-config-file.ts`        | Loading `logixia.config.json` from disk        |

---

## DOCS-02 🟡 Add JSDoc to all public methods

### Priority: `LogixiaLogger` class methods

```typescript
/**
 * Creates a child logger that inherits this logger's config and transport
 * but operates with its own context string.
 *
 * Child loggers share the parent's transports — they do NOT create new
 * file handles or database connections.
 *
 * @param context - A label for this child (e.g. 'UserService', 'PaymentFlow')
 * @param data    - Additional structured fields to include in every log entry
 *
 * @example
 * const reqLogger = logger.child('UserController', { userId: req.user.id });
 * reqLogger.info('Profile fetched');
 * // → { context: 'UserController', userId: 42, message: 'Profile fetched', ... }
 */
child(context: string, data?: Record<string, JsonValue>): LogixiaLogger<TLevels>
```

Priority classes / functions to document:

- `createLogger()` — explain the generic type parameter
- All `LogixiaLogger` public methods
- `TransportManager` public methods
- `SearchManager.search()` / `indexLog()`
- `runWithTraceId()` / `extractTraceId()`
- `serializeError()`
- All transport constructors

---

## DOCS-03 🟡 Architecture diagram missing

A diagram that shows:

```
Application Code
      │
      ▼
LogixiaLogger (core)
      │
      ├── TransportManager
      │       ├── ConsoleTransport
      │       ├── FileTransport ──── rotation ── compression
      │       ├── DatabaseTransport (Mongo / PG / MySQL / SQLite)
      │       └── AnalyticsTransport (Mixpanel / Datadog / Segment / GA)
      │
      ├── SearchManager
      │       ├── BasicSearchEngine (inverted index)
      │       ├── NLPSearchEngine (query parser)
      │       ├── PatternRecognitionEngine
      │       └── CorrelationEngine
      │
      └── TraceContext (AsyncLocalStorage)
              └── TraceMiddleware (Express / NestJS)
```

Create this as:

1. An ASCII diagram in the README (quick, no build step)
2. A Mermaid diagram in `docs/architecture.md` (renders on GitHub)

---

## DOCS-04 🟡 Migration guide from winston and pino

Many potential adopters will be migrating from winston or pino. A migration guide
lowers the barrier significantly.

**`docs/MIGRATION.md`:**

```markdown
# Migration Guide

## From Winston

### Basic logging
```

// Winston
const logger = winston.createLogger({ level: 'info', transports: [...] });
logger.info('hello', { key: 'value' });

// Logixia
const logger = createLogger({ level: 'info', transports: [...] });
await logger.info('hello', { key: 'value' });

```

### Custom transports
Winston transports implement `write(chunk, encoding, callback)`.
Logixia transports implement `write(entry: LogEntry): Promise<void>`.

### Metadata
Winston uses `logger.info('msg', { meta: 'data' })` — Logixia is identical.

## From Pino

### Child loggers
```

// Pino
const child = logger.child({ requestId: '123' });

// Logixia
const child = logger.child('RequestHandler', { requestId: '123' });

```

```

---

## DOCS-05 🟡 CLI reference — add to README and expand CLI-GUIDE.md

The existing `docs/CLI-GUIDE.md` is a start but missing:

- Exit codes
- Environment variable support (`LOGIXIA_LOG_FILE`, `LOGIXIA_CONFIG`)
- Error messages and troubleshooting
- Shell completion setup

Add a "CLI Quick Reference" card to the README:

````markdown
## CLI Quick Reference

```bash
# Search logs
logixia search --query "payment failed" --level error --last 1h

# Real-time tail
logixia tail --level warn --follow

# Statistics
logixia stats --group-by service --format table

# Export
logixia export --format csv --output ./report.csv --last 24h

# Analyze
logixia analyze --file ./logs/app.log --last 7d
```
````

````

---

## DOCS-06 🟢 Add "Tested on" runtime compatibility table to README

```markdown
## Runtime Compatibility

| Runtime | Version | Status |
|---------|---------|--------|
| Node.js | 18, 20, 22 | ✅ Tested in CI |
| Bun | 1.x | ✅ Compatible |
| Deno | 1.x (node compat) | ⚠️ Untested |

**Frameworks:** Express 4.x, NestJS 10.x+
**Databases:** MongoDB 6+, PostgreSQL 14+, MySQL 8+, SQLite 3+
````

---

## DOCS-07 🟢 Add `CHANGELOG.md`

Start with `v1.0.0` and keep it updated per release.
Use the **Keep a Changelog** format: https://keepachangelog.com

Tools:

- `standard-version` is already in devDependencies — run `npm run release`
- Or use `changesets` for monorepo-friendly changelog management

```markdown
# Changelog

## [Unreleased]

## [1.0.4] - 2026-03-14

### Fixed

- Removed self-referential `logixia` entry from `dependencies`
- Fixed `createLogger` factory calling private `log()` method
- Replaced all `console.*` leaks in library source with internal logger
- Fixed `LogixiaLoggerModule.forRoot()` using `Date.now()` for trace IDs
```

---

## DOCS-08 🟢 Add "Troubleshooting" section to README

Most common issues developers hit:

```markdown
## Troubleshooting

**Q: My logs aren't showing up in the file**
A: Make sure the directory exists. Logixia creates the file but not parent directories.
Add `fs.mkdirSync('./logs', { recursive: true })` before creating the logger.

**Q: NestJS bootstrap logs (before `LogixiaLoggerModule.forRoot()`) are missing**
A: Use `app.useLogger()` after `NestFactory.create()`:
`const app = await NestFactory.create(AppModule, { logger: false });`
`app.useLogger(app.get(LogixiaLoggerService));`

**Q: Trace ID is always undefined**
A: The trace middleware must be registered before your route handlers.
With `LogixiaLoggerModule.forRoot()` this is automatic. For Express,
call `app.use(createTraceMiddleware())` before `app.use(router)`.

**Q: Custom log levels are missing TypeScript IntelliSense**
A: Use the generic: `createLogger<'payment' | 'order'>({ customLevels: { ... } })`
without the generic, TypeScript cannot infer the extra methods.

**Q: Database transport not writing logs**
A: Check the connection URL and ensure the optional dependency is installed:
`npm install mongodb` (or `pg`, `mysql2`, `sqlite3`).
Run `await logger.healthCheck()` to see which transports are unhealthy.
```
