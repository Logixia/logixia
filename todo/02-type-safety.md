# 02 — Type Safety

> Logixia ships with `strict: true` in tsconfig but has several `any` escape hatches
> that undermine the whole promise. Every item here needs to be fixed before we can
> truthfully advertise "zero `any`" and "strictly typed throughout".

---

## TS-01 🟠 `[K: string]: any` index signature on `LogixiaLogger`

**File:** `src/core/logitron-logger.ts`
**Why it exists:** To let the factory function attach dynamic custom-level methods
(`logger.payment()`, `logger.order()`, etc.) without a TypeScript error.

**Why it's bad:**
```typescript
// With [K: string]: any, ALL of these are valid — no protection at all:
logger.anythingAtAll()        // no error
logger.undefinedMethod(99)    // no error
logger['__proto__'] = {}      // no error
```

### Fix — use a generic type parameter instead

The types file already defines `ILogger<TLevels>` which models custom levels correctly.
The issue is that `LogixiaLogger` doesn't narrow itself to that generic.

```typescript
// Step 1: make LogixiaLogger generic
class LogixiaLogger<TLevels extends string = never>
  implements ILogger<TLevels> {
  // Remove the [K: string]: any index signature
}

// Step 2: the factory returns the correct generic
export function createLogger<TLevels extends string = never>(
  config: LoggerConfig<TLevels>
): LogixiaLogger<TLevels> {
  const logger = new LogixiaLogger<TLevels>(config);
  // attach dynamic methods...
  return logger;
}

// Step 3: consumer gets full type safety
const logger = createLogger({
  customLevels: {
    payment: { ... },
    order:   { ... },
  }
});

logger.payment('charged');     // ✓ — typed
logger.order('placed');        // ✓ — typed
logger.anythingElse('oops');   // ✗ — compile error
```

The `ILogger<TLevels>` type in `src/types/index.ts` already has the right mapped type:
```typescript
type CustomLevelMethods<TLevels extends string> = {
  [K in TLevels]: (message: string, data?: unknown) => Promise<void>;
};
```
`LogixiaLogger` just needs to extend `CustomLevelMethods<TLevels>` and drop the escape hatch.

---

## TS-02 🟠 `DatabaseTransport.connection: any`

**File:** `src/transports/database.transport.ts`
**Line:** ~15

### What's wrong
```typescript
class DatabaseTransport implements IAsyncTransport {
  private connection: any;  // ← could be MongoClient, pg.Pool, mysql.Connection, sqlite.Database
```

### Fix — use a discriminated union

```typescript
import type { MongoClient } from 'mongodb';
import type { Pool as PgPool } from 'pg';
import type { Connection as MySqlConnection } from 'mysql2/promise';
import type { Database as SQLiteDatabase } from 'sqlite';

type DBConnection =
  | { type: 'mongodb';  client: MongoClient }
  | { type: 'postgres'; client: PgPool }
  | { type: 'mysql';    client: MySqlConnection }
  | { type: 'sqlite';   client: SQLiteDatabase };

class DatabaseTransport implements IAsyncTransport {
  private connection: DBConnection | null = null;
```

Because the drivers are **optional peer dependencies**, use conditional imports:
```typescript
// Only import type — never import the value when it may not be installed
let mongoClientClass: typeof import('mongodb').MongoClient | undefined;
try {
  mongoClientClass = (await import('mongodb')).MongoClient;
} catch { /* optional peer dep */ }
```

---

## TS-03 🟠 Dynamic method creation in factory bypasses type checker

**File:** `src/core/logitron-logger.ts` (`createLogger` function)

### What's wrong
```typescript
for (const levelName of Object.keys(config.customLevels ?? {})) {
  (logger as Record<string, unknown>)[levelName] = async (...) => { ... };
}
```
This uses a runtime cast to `Record<string, unknown>` — same problem as `any`.

### Fix — follow the `ILogger<TLevels>` contract

After implementing TS-01, the factory becomes:
```typescript
export function createLogger<TLevels extends string = never>(
  config: LoggerConfig<TLevels>,
): LogixiaLogger<TLevels> {
  const logger = new LogixiaLogger<TLevels>(config);

  // Attach custom levels — still runtime but now the RETURN TYPE is correct
  for (const levelName of (Object.keys(config.customLevels ?? {})) as TLevels[]) {
    // Safe because we know levelName ∈ TLevels
    (logger as ILogger<TLevels>)[levelName] = async (
      message: string,
      data?: unknown,
    ): Promise<void> => {
      await logger.logLevel(levelName, message, data);
    };
  }

  return logger;
}
```
The caller's type `logger.payment` is still inferred from `TLevels` — the cast only
happens once, internally, not at every call site.

---

## TS-04 🟡 `LogixiaLoggerService` methods lack `data` typing

**File:** `src/core/logitron-nestjs.service.ts`

### What's wrong
```typescript
async info(message: string, data?: unknown): Promise<void>
```
`data?: unknown` forces consumers to cast when they pass structured objects.

### Fix — use the same `LogMeta` / `ContextData` union already in types
```typescript
// In src/types/index.ts (already exists or add it)
export type LogPayload = Record<string, JsonValue | Error | undefined> | JsonValue | undefined;

// In service
async info(message: string, data?: LogPayload): Promise<void>
```
This mirrors what reixo does with `LogMeta` and gives consumers IntelliSense on the data shape.

---

## TS-05 🟡 `SearchFilters.customFields` too loose

**File:** `src/search/types/search.types.ts`

### What's wrong
```typescript
interface SearchFilters {
  customFields?: Record<string, unknown>;   // ← any value accepted
}
```

### Fix
```typescript
interface SearchFilters {
  customFields?: Record<string, string | number | boolean | null>;
}
```
Custom fields in logs are primitives. Allowing arbitrary objects opens the door to
unexpected serialization bugs and makes IntelliSense useless.

---

## TS-06 🟡 `LogEntry.payload` typed as `unknown` — narrows too aggressively at use sites

**File:** `src/types/index.ts`

```typescript
interface LogEntry {
  payload?: unknown;
}
```
Every consumer has to cast before reading. Define a `LogPayload` union and use it:

```typescript
export type JsonPrimitive = string | number | boolean | null;
export type JsonObject    = { [K in string]?: JsonValue };
export type JsonArray     = JsonValue[];
export type JsonValue     = JsonPrimitive | JsonObject | JsonArray;

export type LogPayload = JsonValue | Error | undefined;

interface LogEntry {
  payload?: LogPayload;
}
```

---

## TS-07 🟢 Missing return-type annotations on several public methods

Run the following to find all public methods missing explicit return types:

```bash
npx tsc --noEmit --strict 2>&1 | grep "implicit return"
```

Files most likely to have this issue:
- `src/search/core/basic-search-engine.ts` (long class, mixed return types)
- `src/transports/transport.manager.ts` (metrics methods)
- `src/cli/commands/*.ts` (all Commander action handlers)

Add explicit return types to all `public` and `export`ed functions.

---

## TS-08 🟢 `error.utils.ts` uses `any` internally

**File:** `src/utils/error.utils.ts`

```typescript
function serializeError(error: unknown, options?: SerializeOptions): any {  // ← any
```

Fix:
```typescript
export type SerializedError = {
  name: string;
  message: string;
  stack?: string;
  cause?: SerializedError;
  [key: string]: JsonValue | SerializedError | undefined;
};

export function serializeError(error: unknown, options?: SerializeOptions): SerializedError
```

---

## TS-09 🟢 Transport-level configuration union not exhaustive

**File:** `src/types/transport.types.ts`

The `TransportConfig` type is a union but the exhaustiveness check is missing in the
transport factory. Add:

```typescript
// In transport.manager.ts — createTransport switch
function createTransport(config: TransportConfig): ITransport {
  switch (config.type) {
    case 'console':  return new ConsoleTransport(config);
    case 'file':     return new FileTransport(config);
    case 'database': return new DatabaseTransport(config);
    case 'mixpanel': return new MixpanelTransport(config);
    case 'datadog':  return new DatadogTransport(config);
    case 'segment':  return new SegmentTransport(config);
    case 'google-analytics': return new GoogleAnalyticsTransport(config);
    default: {
      // Exhaustiveness check — TypeScript errors if a new type is added without a case
      const _exhaustive: never = config;
      throw new Error(`Unknown transport type: ${JSON.stringify(_exhaustive)}`);
    }
  }
}
```

---

## Zero-`any` Verification Workflow

After all fixes:

```bash
# Should output 0 errors
npx tsc --noEmit --strict --skipLibCheck

# Grep for remaining any (should be empty except comments)
grep -rn ": any\b\|as any\b" src/ | grep -v "//.*any"
```

Target: **0 explicit `any` in `src/`**.
