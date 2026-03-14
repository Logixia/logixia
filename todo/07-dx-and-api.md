# 07 — Developer Experience & API Quality

> These items won't crash production but they directly affect how quickly
> developers adopt logixia, how often they come back to the docs, and how
> they talk about it to peers.

---

## DX-01 🟡 Config duplication — DEFAULT_CONFIG defined in three places

**Files:**

- `src/core/logitron-logger.ts` — inline defaults
- `src/core/logitron-nestjs.service.ts` — duplicated inline defaults
- `src/core/logitron-logger.module.ts` — partial defaults again

### Fix — single source of truth

```typescript
// src/config/defaults.ts  (new file)
import type { LoggerConfig } from '../types';

export const DEFAULT_LOGGER_CONFIG: Required<
  Pick<LoggerConfig, 'level' | 'appName' | 'format' | 'showTimestamp' | 'showAppName'>
> = {
  level: 'info',
  appName: 'App',
  format: 'text',
  showTimestamp: true,
  showAppName: true,
};
```

Import `DEFAULT_LOGGER_CONFIG` in every file that needs defaults. No more drift.

---

## DX-02 🟡 Static `loggerConfig` on `LogixiaLoggerModule` breaks parallel tests

**File:** `src/core/logitron-logger.module.ts`
**Line:** ~59

```typescript
// Current
export class LogixiaLoggerModule {
  static loggerConfig: LoggerConfig = DEFAULT_CONFIG;   // static = shared across instances!
```

In Jest test suites that call `Test.createTestingModule()` twice with different
configs, the second call reads the first call's config from the static property.

### Fix — remove the static property and rely exclusively on the DI token

```typescript
// forRoot() — store config via InjectionToken, not static property
static forRoot(config?: Partial<LoggerConfig>): DynamicModule {
  const resolvedConfig = { ...DEFAULT_LOGGER_CONFIG, ...config };
  return {
    module: LogixiaLoggerModule,
    global: true,
    providers: [
      {
        provide: LOGIXIA_LOGGER_CONFIG,
        useValue: resolvedConfig,
      },
      LogixiaLoggerService,
      // trace middleware providers...
    ],
    exports: [LogixiaLoggerService],
  };
}
```

Any provider that previously read `LogixiaLoggerModule.loggerConfig` should instead
inject `@Inject(LOGIXIA_LOGGER_CONFIG) private config: LoggerConfig`.

---

## DX-03 🟡 `forFeature(context)` — no way to dispose a feature logger

**File:** `src/core/logitron-logger.module.ts`

`forFeature()` creates a new logger instance per context, but there's no `OnModuleDestroy`
lifecycle hook to close/flush it when the module is torn down.

### Fix

```typescript
@Injectable()
export class FeatureLoggerService implements OnModuleDestroy {
  constructor(
    @Inject(LOGIXIA_LOGGER_CONFIG) private config: LoggerConfig,
    @Inject(FEATURE_CONTEXT) private context: string
  ) {
    this.logger = createLogger({ ...config, defaultContext: context });
  }

  async onModuleDestroy(): Promise<void> {
    await this.logger.close();
  }
}
```

---

## DX-04 🟡 No Zod schema validation for `LoggerConfig`

Users currently get a runtime crash with an unhelpful message if they pass a bad config.
Zod validation gives them an actionable error at construction time.

```typescript
// src/config/schema.ts
import { z } from 'zod';

export const LoggerConfigSchema = z.object({
  appName:       z.string().min(1).default('App'),
  level:         z.enum(['error', 'warn', 'info', 'debug', 'trace', 'verbose']).default('info'),
  format:        z.enum(['json', 'text']).default('text'),
  showTimestamp: z.boolean().default(true),
  transports:    z.array(TransportConfigSchema).optional(),
  customLevels:  z.record(CustomLevelConfigSchema).optional(),
}).strict();

// In LogixiaLogger constructor
constructor(config: LoggerConfig) {
  const parsed = LoggerConfigSchema.safeParse(config);
  if (!parsed.success) {
    throw new Error(
      `Invalid logixia config:\n${parsed.error.issues.map(i => `  ${i.path.join('.')}: ${i.message}`).join('\n')}`
    );
  }
  this.config = parsed.data;
}
```

Zod is a lightweight optional dependency — only add it if you want schema validation,
otherwise keep it as a devDependency and do manual validation.

Alternatively, use the lighter `@sinclair/typebox` which generates both TypeScript
types and JSON Schema validation from a single definition — no runtime Zod needed.

---

## DX-05 🟡 `healthCheck()` return type is not clearly documented

**File:** `src/core/logitron-logger.ts`

```typescript
// Current — return type is implicit
async healthCheck() {
  // returns something about transports...
}
```

### Fix — explicit, documented return type

```typescript
export interface HealthCheckResult {
  healthy: boolean;
  transports: Array<{
    id:      string;
    type:    string;
    healthy: boolean;
    error?:  string;
  }>;
  timestamp: string;
}

async healthCheck(): Promise<HealthCheckResult> { ... }
```

---

## DX-06 🟡 `child()` method — no TypeScript typing for merged context

**File:** `src/core/logitron-logger.ts`

```typescript
// Current
child(context: string, data?: unknown): LogixiaLogger
// 'data' is the extra context fields but typed as 'unknown' — useless IntelliSense
```

### Fix

```typescript
child<TExtra extends Record<string, JsonValue> = Record<never, never>>(
  context: string,
  data?: TExtra,
): LogixiaLogger<TLevels>
```

---

## DX-07 🟢 Transport IDs — no enforced uniqueness

**File:** `src/transports/transport.manager.ts`

If two transports share the same `id`, `setTransportLevels('console', ...)` becomes
ambiguous.

### Fix

```typescript
constructor(transports: TransportConfig[]) {
  const ids = transports.map(t => t.id ?? t.type);
  const duplicates = ids.filter((id, i) => ids.indexOf(id) !== i);
  if (duplicates.length > 0) {
    throw new Error(`Duplicate transport IDs: ${duplicates.join(', ')}`);
  }
}
```

---

## DX-08 🟢 `setTransportLevels()` — no feedback when transport ID not found

**Current behaviour:** silently does nothing if the transport ID doesn't exist.

```typescript
// Add a guard
setTransportLevels(transportId: string, levels: LogLevelString[]): void {
  const transport = this.transports.find(t => t.id === transportId);
  if (!transport) {
    internalWarn(`setTransportLevels: transport "${transportId}" not found. Available: ${this.transports.map(t => t.id).join(', ')}`);
    return;
  }
  // ...
}
```

---

## DX-09 🟢 Add `logixia.config.ts` TypeScript-first config file support

Many developers prefer a typed config file instead of inline configuration:

```typescript
// logixia.config.ts
import { defineConfig } from 'logixia';

export default defineConfig({
  appName: 'payments-service',
  level: 'info',
  transports: [
    { type: 'console', format: 'json' },
    { type: 'file', filename: './logs/app.log', rotate: '1d' },
  ],
});
```

Implementation:

```typescript
// src/config/define-config.ts
export function defineConfig<TLevels extends string = never>(
  config: LoggerConfig<TLevels>
): LoggerConfig<TLevels> {
  return config; // identity function — value is just for IntelliSense
}
```

The CLI can then load `logixia.config.ts` via `tsx` or `jiti`:

```typescript
// src/cli/utils.ts
async function loadConfig(): Promise<LoggerConfig | null> {
  try {
    const mod = await import(join(process.cwd(), 'logixia.config'));
    return mod.default ?? mod;
  } catch {
    return null;
  }
}
```

---

## DX-10 🟢 Add `transport:error` event to enable external error monitoring

```typescript
// In LogixiaLogger — extends EventEmitter
class LogixiaLogger<TLevels extends string = never>
  extends EventEmitter
  implements ILogger<TLevels>
{
  // Emit structured event instead of silent console.error
  private handleTransportError(transportId: string, error: unknown): void {
    this.emit('transport:error', { transportId, error, timestamp: new Date().toISOString() });
  }
}

// Consumer
logger.on('transport:error', ({ transportId, error }) => {
  alertingService.notify(`Logixia transport ${transportId} failed: ${error}`);
});
```

This is a common pattern in winston and pino — it makes logixia production-friendly
for teams that monitor their own observability infrastructure.
