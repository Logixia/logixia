# 01 — Critical Bugs

> All items here are 🔴 P0 or 🟠 P1. Ship nothing else until these are resolved.

---

## BUG-01 🔴 Self-referential `dependencies` entry in `package.json`

**File:** `package.json`
**Line:** ~149
**Severity:** P0 — Breaks `npm install` for any downstream consumer

### What's wrong
```json
"dependencies": {
  "chalk": "^5.3.0",
  "commander": "^11.1.0",
  "inquirer": "^9.2.12",
  "ora": "^7.0.1",
  "logixia": "^1.0.3"   // ← THE LIBRARY DEPENDS ON ITSELF
}
```
When someone runs `npm install logixia`, npm tries to resolve `logixia@^1.0.3` as a dependency
of `logixia`, creating a circular resolution loop. In npm v7+ this typically results in an
`ERESOLVE` error or installs a second, identical copy of the package into itself.

### Fix
Remove the `"logixia"` entry from `dependencies` entirely.

```json
// BEFORE
"dependencies": {
  "chalk": "^5.3.0",
  "commander": "^11.1.0",
  "inquirer": "^9.2.12",
  "ora": "^7.0.1",
  "logixia": "^1.0.3"
}

// AFTER
"dependencies": {
  "chalk": "^5.3.0",
  "commander": "^11.1.0",
  "inquirer": "^9.2.12",
  "ora": "^7.0.1"
}
```

### Verification
```bash
npm pack --dry-run   # should show no circular dependency warning
npm install          # should succeed in a clean node_modules
```

---

## BUG-02 🔴 `createLogger` factory calls a private method — TypeScript crash

**File:** `src/core/logitron-logger.ts`
**Line:** ~597
**Severity:** P0 — Calling a private method at runtime produces a TypeError in strict mode
and a compile error under `--strict`.

### What's wrong
```typescript
// Inside createLogger() factory function
logger[levelName] = async (message: string, data?: unknown) => {
  await logger.log(levelName, message, data);   // ← log() is private!
};
```

The `log()` method is declared `private` on `LogixiaLogger`. Accessing it via bracket
notation circumvents the TypeScript compiler (because of the `[K: string]: any` index
signature) but the intent is broken — and in strict environments or with
`noImplicitAny: true` without the escape hatch, this will fail to compile.

### Fix — Option A (preferred): use the public `logLevel()` method

```typescript
logger[levelName] = async (message: string, data?: unknown) => {
  await logger.logLevel(levelName, message, data);   // ← public API
};
```

### Fix — Option B: promote `log()` to `protected`

```typescript
// Change declaration in LogixiaLogger
protected async log(level: string, message: string, data?: unknown): Promise<void> {
```

Only choose Option B if subclasses need direct access to `log()`.
Option A is cleaner — it uses the documented public API.

---

## BUG-03 🟠 `console.log` / `console.error` leaks inside library source

**Severity:** P1 — Pollutes consumer application output; impossible to suppress;
breaks any "silence all output" testing approach.

### Affected locations

| File | Line(s) | Call |
|------|---------|------|
| `src/core/logitron-logger.ts` | 227, 232 | `console.error(...)` in flush |
| `src/core/logitron-logger.ts` | 284, 292, 300 | `console.warn(...)` transport fallback |
| `src/core/logitron-logger.ts` | 316, 325 | `console.error(...)` healthCheck |
| `src/utils/error.utils.ts` | 248 | `console.error(...)` in serializeError |
| `src/transports/transport.manager.ts` | 556–559 | `console.error(...)` fallback |

### Fix
Create an internal `internalLog(level, message)` helper that:
1. Checks whether a `debug` or `verbose` level is enabled on the current logger instance
2. Falls back to `process.stderr.write` only if no transport is available yet
3. Is never sent to any user-configured transport

```typescript
// src/utils/internal-log.ts  (new file)
export function internalWarn(message: string, error?: unknown): void {
  const prefix = '[logixia internal]';
  if (process.env.LOGIXIA_DEBUG === '1') {
    process.stderr.write(`${prefix} WARN  ${message}\n`);
    if (error) process.stderr.write(String(error) + '\n');
  }
}

export function internalError(message: string, error?: unknown): void {
  const prefix = '[logixia internal]';
  process.stderr.write(`${prefix} ERROR ${message}\n`);
  if (error instanceof Error) process.stderr.write(error.stack ?? error.message + '\n');
}
```

Replace every `console.error(...)` / `console.warn(...)` in source with the appropriate
`internalWarn` / `internalError` call.

---

## BUG-04 🟠 Silent `.catch(console.error)` in `LogixiaLoggerService`

**File:** `src/core/logitron-nestjs.service.ts`
**Lines:** 63, 75, 78 (approximate)
**Severity:** P1 — Swallows every transport or formatting error silently.
NestJS apps will have invisible logging failures in production.

### What's wrong
```typescript
async info(message: string, data?: unknown): Promise<void> {
  this.logger.info(message, data).catch(console.error);  // ← silent swallow
}
```

### Fix
Use a structured error that is emitted on the logger's event bus so consumers can
subscribe and handle it:

```typescript
// Option A — emit on internal event emitter
async info(message: string, data?: unknown): Promise<void> {
  try {
    await this.logger.info(message, data);
  } catch (err) {
    // Don't swallow — re-emit so the app can decide what to do
    this.logger.emit?.('transport:error', { method: 'info', error: err });
    internalError('LogixiaLoggerService.info failed', err);
  }
}

// Option B — expose an onError callback in LoggerConfig
// config.onInternalError: (err: Error) => void
```

At minimum, replace `.catch(console.error)` with `.catch(err => internalError(..., err))`
so the error is written to stderr and not silently discarded.

---

## BUG-05 🟠 Trace-ID generator collision risk in `LogixiaLoggerModule`

**File:** `src/core/logitron-logger.module.ts`
**Lines:** 79–83
**Severity:** P1 — Under moderate concurrent request load, `Date.now().toString(36)`
produces duplicate trace IDs because it only has millisecond resolution.

### What's wrong
```typescript
generateTraceId: () =>
  Date.now().toString(36) +           // ms-resolution = duplicates under load
  Math.random().toString(36).slice(2) // short — only ~11 chars of entropy
```

### Fix
Use the same `generateTraceId()` from `src/utils/trace.utils.ts` which correctly
generates a UUID v4:

```typescript
import { generateTraceId } from '../utils/trace.utils';

// In forRoot() default config:
generateTraceId: generateTraceId,  // already a UUID v4 generator
```

This is a one-line change and the utility already exists.

---

## BUG-06 🟠 `FileTransport.writeStream` — stream not closed on `close()`

**File:** `src/transports/file.transport.ts`
**Severity:** P1 — In long-running processes, calling `logger.close()` does not end
the write stream, causing the process to hang on `process.exit()`.

### Fix
```typescript
async close(): Promise<void> {
  // Flush pending batch first
  if (this.batch.length > 0) {
    await this.writeBatch(this.batch);
    this.batch = [];
  }

  // THEN close the stream
  if (this.writeStream && !this.writeStream.destroyed) {
    await new Promise<void>((resolve, reject) => {
      this.writeStream!.end((err?: Error | null) => {
        if (err) reject(err);
        else resolve();
      });
    });
  }

  clearInterval(this.flushInterval);
}
```

---

## BUG-07 🟠 NestJS module `static loggerConfig` — not safe for tests

**File:** `src/core/logitron-logger.module.ts`
**Line:** ~59
**Severity:** P1 — Static class property persists across Jest test runs that use
multiple `Test.createTestingModule()` calls. The second module receives the first
module's config.

### Fix
Replace the static property with a NestJS `InjectionToken`:

```typescript
// Replace
static loggerConfig: LoggerConfig = DEFAULT_CONFIG;

// With — store on the module instance via DI
// Use LOGIXIA_LOGGER_CONFIG token (already exists) consistently
```

Detail in `07-dx-and-api.md`.

---

## Patch-Release Checklist

After fixing all the above:

1. `npm version patch` → bumps to `1.0.4`
2. Run `npm pack --dry-run` — verify self-dep is gone
3. Run `npm test` — all existing tests pass
4. `npm publish --access public`
5. Tag release in GitHub as `v1.0.4 — critical bug fixes`
