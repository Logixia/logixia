---
title: Plugins
description: Extend logixia with plugins that enrich, filter or observe every log entry, react to transport failures and run shutdown hooks, per logger or globally.
order: 14
---

# Plugins

A plugin is an object with a `name` and optional lifecycle hooks. Use one to enrich entries, drop some, forward transport failures to an alerting system, or collect metrics (the [metrics](/guide/metrics) feature is a plugin).

```ts
import { createLogger } from 'logixia';
import type { LogixiaPlugin } from 'logixia';

const buildTag: LogixiaPlugin = {
  name: 'build-tag',
  onLog(entry) {
    return { ...entry, payload: { ...entry.payload, buildId: process.env['BUILD_ID'] } };
  },
  onError(error) {
    console.error('transport failed:', error.message);
  },
};

const logger = createLogger({ appName: 'api' });
logger.use(buildTag);
```

## Hooks

| Hook                     | When                                                                                                                                                               |
| ------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `onInit()`               | Once, right after `logger.use(plugin)`. Rejections are swallowed.                                                                                                  |
| `onLog(entry)`           | For every entry that passes level checks and sampling, after redaction and before transports. Return the entry (changed or not) to continue, or `null` to drop it. |
| `onError(error, entry?)` | When a transport write fails.                                                                                                                                      |
| `onShutdown()`           | When the logger is closed.                                                                                                                                         |

Plugins run in registration order and each receives the previous plugin's output. Errors thrown inside a hook are swallowed, so a faulty plugin cannot break logging; when `onLog` throws, the chain continues with the entry as it was before that plugin.

Because `onLog` runs after redaction, a plugin never sees values that [`redact`](/guide/redaction) removed.

## Dropping entries

```ts
import { createLogger } from 'logixia';
import type { LogixiaPlugin } from 'logixia';

const logger = createLogger({ appName: 'api' });

const dropHealthChecks: LogixiaPlugin = {
  name: 'drop-health-checks',
  onLog(entry) {
    return entry.payload?.['route'] === '/health' ? null : entry;
  },
};

logger.use(dropHealthChecks);
```

## Per logger or global

`logger.use(plugin)` registers on that logger and its children; `logger.unuse(name)` removes it. `usePlugin(plugin)` registers globally, and applies to loggers created afterwards:

```ts
import { createLogger, usePlugin } from 'logixia';

usePlugin({ name: 'global-audit', onLog: (entry) => entry });

const logger = createLogger({ appName: 'api' });
await logger.info('includes the global plugin');
```

`logger.use()` is typed as accepting `{ name: string }`, so declare plugins as `LogixiaPlugin` variables (as above) rather than passing an inline object literal with hooks, which TypeScript rejects. A plugin name can be registered once per logger. `globalPluginRegistry` and `PluginRegistry` are exported for advanced use.
