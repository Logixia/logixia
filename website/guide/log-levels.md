---
title: Log levels
description: Built-in and custom logixia log levels, how the active level is chosen, runtime changes, per-namespace levels and the LOGIXIA_LEVEL environment variable.
order: 4
---

# Log levels

A level is a name with a number. An entry is written when its number is less than or equal to the logger's active level number, so a lower number means more severe.

## Built-in levels

| Level     | Number | Method                            |
| --------- | ------ | --------------------------------- |
| `error`   | 0      | `logger.error(msgOrError, data?)` |
| `warn`    | 1      | `logger.warn(msg, data?)`         |
| `info`    | 2      | `logger.info(msg, data?)`         |
| `debug`   | 3      | `logger.debug(msg, data?)`        |
| `trace`   | 4      | `logger.trace(msg, data?)`        |
| `verbose` | 5      | `logger.verbose(msg, data?)`      |

The default level is `info`, so `debug`, `trace` and `verbose` are dropped. There is also `logger.logLevel(level, message, data?)` for logging at a level chosen at runtime. The `LogLevel` constant exports the built-in names (`LogLevel.INFO` is `'info'`).

```ts
import { createLogger, LogLevel } from 'logixia';

const logger = createLogger({
  appName: 'api',
  levelOptions: { level: LogLevel.DEBUG, colors: { debug: 'green', info: 'blue' } },
});

await logger.debug('cache lookup', { key: 'user:42' });
await logger.logLevel('info', 'same as logger.info');
```

## Custom levels

Add levels in `levelOptions.levels`. `createLogger()` turns each name into a typed method.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'payments',
  levelOptions: {
    level: 'info',
    levels: { error: 0, warn: 1, audit: 1, info: 2, debug: 3 },
    colors: { audit: 'magenta' },
  },
});

await logger.audit('refund issued', { refundId: 'rf_1' });
```

Notes:

- Built-in levels always exist, even if you leave them out of `levels`.
- A custom level has the priority you give it. `audit: 1` is shown whenever the active level is `warn` or more verbose.
- `logLevel()` drops a level name that is neither built in nor registered in `levels`.
- A custom level without a configured color is given one from a small palette in the default text output.

## How the active level is chosen

At creation, the first match wins:

1. `LOGIXIA_LEVEL` environment variable, if it names a known level (case-insensitive). An unknown value is reported once and skipped.
2. `levelOptions.level`.
3. A `NODE_ENV` default: `debug` for `development`, `warn` for `test`, `info` for `production`.
4. `info`.

::: warning NODE_ENV defaults need levelOptions
Because the logger starts from a default config that already contains `level: 'info'`, step 3 only applies when you pass `levelOptions` without a `level` (for example only `levels` or `colors`). A logger created with no `levelOptions` is `info` regardless of `NODE_ENV`. Set the level explicitly, or use `LOGIXIA_LEVEL`, when you want it to vary by environment.
:::

On every call, the effective level for a logger is resolved in this order:

1. A level set with `setLevel()`.
2. `LOGIXIA_LEVEL_<NS>` for the logger's namespace.
3. A matching `namespaceLevels` entry.
4. `LOGIXIA_LEVEL`.
5. The configured level.

## Change the level at runtime

```ts
import { createLogger } from 'logixia';

const logger = createLogger({ appName: 'api' });

logger.setLevel('debug');
console.log(logger.getLevel()); // 'debug'
```

`setLevel()` outranks every other source and applies to that logger instance only. A child created earlier keeps its own level; a child created afterwards starts from the parent's current level. An unknown level name is ignored with a warning and the current level is kept. `getLevel()` returns the configured level, not a per-namespace one.

### Flip levels from outside the process

`registerLevelSignal()` cycles the level each time the process receives a signal (default `SIGUSR2`), which is enough to turn verbosity up and back down with `kill -USR2 <pid>`:

```ts
import { createLogger, registerLevelSignal } from 'logixia';

const logger = createLogger({ appName: 'api' });

const dispose = registerLevelSignal(logger, {
  signal: 'SIGUSR2',
  cycle: ['info', 'debug', 'trace'],
});

// Later, to remove the listener:
dispose();
```

`createLevelControlHandler()` returns a Node `http` and Express-compatible handler: `GET` returns `{ level, namespaceLevels }`, and `POST` with a JSON body `{ "level": "debug", "namespaceLevels": { "db.*": "debug" } }` applies them.

```ts
import express from 'express';
import { createLevelControlHandler, createLogger } from 'logixia';

const logger = createLogger({ appName: 'api' });
const app = express();

app.all('/admin/log-level', requireAdmin, createLevelControlHandler(logger));

function requireAdmin(
  req: express.Request,
  res: express.Response,
  next: express.NextFunction
): void {
  if (req.headers['x-admin-token'] !== process.env['ADMIN_TOKEN']) {
    res.status(403).end();
    return;
  }
  next();
}
```

::: danger The level handler has no authentication
Anyone who can reach it can silence logging or turn on verbose output. Mount it behind your own authentication on an internal route or port. Mutating requests must send `Content-Type: application/json` (otherwise 415) and a body of at most 16 KB (otherwise 413). Unknown levels are rejected with 400; pass `{ allowedLevels: [...] }` to restrict the accepted names.
:::

## Namespaces

A logger's namespace is its context label, the first argument to `child()` (or the second argument to `createLogger`). Use `namespaceLevels` to give namespaces their own level:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  levelOptions: { level: 'info' },
  namespaceLevels: {
    'db.queries': 'debug',
    'http.*': 'warn',
    payment: 'trace',
  },
});

const queries = logger.child('db.queries');
await queries.debug('SELECT 1'); // shown
```

Matching rules:

- Patterns are dot-separated. `*` matches exactly one segment, so `http.*` matches `http.client` but not `http` or `http.client.pool`. There is no `**`.
- When several patterns match, the longest pattern wins.
- A nested child replaces the context instead of extending it: `logger.child('db').child('queries')` has context `queries`, not `db.queries`. Create each namespaced logger directly from the root logger.
- Namespace levels apply to loggers created with a context. The root logger has no namespace.

Change them at runtime with `setNamespaceLevels(map)` (replaces the whole map), `patchNamespaceLevels(map)` (merges) and `getNamespaceLevels()`. These methods exist on the `LogixiaLogger` class, not on the type returned by `createLogger()`:

```ts
import { LogixiaLogger } from 'logixia';

const logger = new LogixiaLogger({ appName: 'api' });

logger.setNamespaceLevels({ 'db.queries': 'debug' });
logger.patchNamespaceLevels({ payment: 'trace' });
console.log(logger.getNamespaceLevels());
```

### Environment overrides

`LOGIXIA_LEVEL_<NS>=<level>` sets the level for a namespace without a code change. The environment key uses the first dot-separated segment of the context, upper-cased: contexts `db` and `db.queries` both read `LOGIXIA_LEVEL_DB`. This is coarser than `namespaceLevels` matching.

```bash
LOGIXIA_LEVEL=warn LOGIXIA_LEVEL_DB=debug node dist/server.js
```
