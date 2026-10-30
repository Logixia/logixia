---
title: Configuration
description: 'Reference for every logixia LoggerConfig option with types and defaults: levels, fields, redaction, sampling, tracing, graceful shutdown and transports.'
order: 3
---

# Configuration

`createLogger(config)` takes a `LoggerConfig` object. Every option is optional. This page lists each one with its type and default, then explains the two output paths, because they decide which options apply.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'billing',
  environment: 'production',
  traceId: true,
  levelOptions: { level: 'info' },
  redact: { autoDetect: true },
  sampling: { rate: 0.5, perLevel: { debug: 0.1 } },
  gracefulShutdown: { enabled: true, timeout: 5000 },
  transports: { console: { format: 'json' } },
});

await logger.info('ready');
```

## Options at a glance

| Option             | Type                                              | Default         | Purpose                                                               |
| ------------------ | ------------------------------------------------- | --------------- | --------------------------------------------------------------------- |
| `appName`          | `string`                                          | `'App'`         | Name written into every entry and the text prefix.                    |
| `environment`      | `'development' \| 'production'`                   | `'development'` | Written into every entry as `environment`.                            |
| `traceId`          | `boolean \| TraceIdConfig`                        | `true`          | Include a trace ID in entries; object form configures NestJS tracing. |
| `format`           | `{ timestamp?, colorize?, json? }`                | see below       | Text and JSON formatting for the default output path.                 |
| `silent`           | `boolean`                                         | `false`         | Drop every entry.                                                     |
| `levelOptions`     | `{ level?, levels?, colors? }`                    | see below       | Active level, custom levels and colors.                               |
| `fields`           | `Partial<Record<LogFieldKey, string \| boolean>>` | all shown       | Hide fields in the default output path.                               |
| `redact`           | `RedactConfig`                                    | none            | Mask sensitive data before any transport sees it.                     |
| `namespaceLevels`  | `Record<string, LogLevelString>`                  | none            | Per-namespace level overrides.                                        |
| `gracefulShutdown` | `boolean \| GracefulShutdownConfig`               | off             | Flush on SIGTERM and SIGINT.                                          |
| `sampling`         | `SamplingConfig`                                  | none            | Rate limiting and sampling.                                           |
| `transports`       | `TransportConfig`                                 | none            | Where entries go. Setting it replaces the default output.             |

`LoggerConfig` also has an index signature (`[key: string]: unknown`), so unknown keys are accepted without a type error. A misspelled option is silently ignored, so check spelling when something has no effect.

## Two output paths

What reaches the terminal depends on whether you set `transports`.

|                                                      | No `transports`                              | With `transports`                                               |
| ---------------------------------------------------- | -------------------------------------------- | --------------------------------------------------------------- |
| Formatter                                            | Built into the logger                        | Each transport formats its own output                           |
| Stream                                               | `error` to stderr, everything else to stdout | Console transport: `error` and `warn` to stderr                 |
| `format.json`, `format.colorize`, `format.timestamp` | Apply                                        | Ignored; set `format`, `colorize`, `timestamp` on the transport |
| `fields`                                             | Apply                                        | Ignored by transports                                           |
| Console output                                       | Always                                       | Only if you list `console`                                      |

The default path is the quickest way to get readable development logs. Once you add `transports`, configure formatting on each transport (see [Console transport](/guide/transports/console)).

```ts
import { createLogger } from 'logixia';

// Default path: format and fields apply.
const dev = createLogger({
  appName: 'api',
  format: { colorize: false, json: true },
});

// Transport path: format lives on the transport.
const prod = createLogger({
  appName: 'api',
  transports: { console: { format: 'json', colorize: false } },
});

await dev.info('default path');
await prod.info('transport path');
```

## `appName`, `environment`, `silent`

`appName` and `environment` are copied into every entry. `silent: true` makes every log call return immediately, which is handy in tests.

## `traceId`

`traceId: true` (the default) puts a trace ID on every entry. The ID comes from the active trace scope (for example a request handled by middleware) or, outside any scope, from a UUID generated once per logger instance. Set `traceId: false` to leave it out. See [Tracing](/guide/tracing).

The object form, `TraceIdConfig`, is read by the NestJS integration:

| Field            | Type                                                       | Default        | Description                                               |
| ---------------- | ---------------------------------------------------------- | -------------- | --------------------------------------------------------- |
| `enabled`        | `boolean`                                                  | required       | Turn trace handling on or off.                            |
| `generator`      | `() => string`                                             | UUID v4        | Create a trace ID when the request has none.              |
| `contextKey`     | `string`                                                   | `'traceId'`    | Key used in the async context store.                      |
| `extractor`      | `{ header?, query?, body?, params? }` (string or string[]) | see tracing    | Where to read an incoming ID. Merged over the defaults.   |
| `responseHeader` | `string \| false`                                          | `'X-Trace-Id'` | Response header for the resolved ID; `false` disables it. |

## `format`

| Field       | Default | Description                               |
| ----------- | ------- | ----------------------------------------- |
| `timestamp` | `true`  | Show the timestamp in text output.        |
| `colorize`  | `true`  | ANSI colors in text output.               |
| `json`      | `false` | One JSON object per line instead of text. |

These apply to the default output path only.

## `levelOptions`

| Field    | Type                               | Default                                                                  | Description                                           |
| -------- | ---------------------------------- | ------------------------------------------------------------------------ | ----------------------------------------------------- |
| `level`  | `string`                           | `'info'`                                                                 | Minimum level that is logged.                         |
| `levels` | `Record<string, number>`           | `error 0, warn 1, info 2, debug 3, trace 4, verbose 5`                   | Level names and their priority. Lower is more severe. |
| `colors` | `Partial<Record<level, LogColor>>` | error red, warn yellow, info blue, debug green, trace gray, verbose cyan | Level colors.                                         |

Available colors: `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`, `gray`, `grey` and the `bright*` variants (`brightRed`, `brightGreen`, `brightYellow`, `brightBlue`, `brightMagenta`, `brightCyan`, `brightWhite`).

::: warning levelOptions is replaced, not merged
Passing `levelOptions` replaces the default `levelOptions` object. If you set only `level`, the default colors are gone and built-in levels print uncolored. Pass `colors` too when you want them. See [Log levels](/guide/log-levels) for how the active level is resolved, including `LOGIXIA_LEVEL` and `NODE_ENV`.
:::

## `fields`

`fields` hides parts of the default text output. A field set to `false` is hidden; any other value, or leaving it out, shows it.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  fields: { timestamp: false, traceId: false, payload: true },
});

await logger.info('compact line');
```

The text formatter reads `timestamp`, `level`, `appName`, `traceId`, `context`, `message` and `payload`. The type also lists `service`, `timeTaken`, `userId`, `sessionId` and `environment` (`LogFieldKey`), but the text formatter does not render those. You can toggle a field per logger at runtime with `enableField(name)`, `disableField(name)`, `isFieldEnabled(name)`, `getFieldState()` and `resetFieldState()`. Each toggle prints a `[logixia]` notice to stderr.

String values are not format templates. Only `false` has an effect.

## `redact`

Masks sensitive values in the payload and message before they reach any transport. Options: `paths`, `excludePaths`, `patterns`, `censor` and `autoDetect`. Full reference in [Redaction](/guide/redaction).

## `namespaceLevels`

Per-namespace level overrides, matched against a child logger's context. See [Log levels](/guide/log-levels).

## `gracefulShutdown`

`true`, or an object:

| Field     | Type                            | Default                 | Description                                      |
| --------- | ------------------------------- | ----------------------- | ------------------------------------------------ |
| `enabled` | `boolean`                       | required                | Register the signal handlers.                    |
| `timeout` | `number`                        | `5000`                  | Milliseconds to wait for transports to flush.    |
| `signals` | `NodeJS.Signals[]`              | `['SIGTERM', 'SIGINT']` | Signals that trigger the flush.                  |
| `exit`    | `'auto' \| 'always' \| 'never'` | `'auto'`                | Whether logixia ends the process after flushing. |

See [Graceful shutdown](/guide/graceful-shutdown).

## `sampling`

| Field              | Type                     | Default   | Description                                            |
| ------------------ | ------------------------ | --------- | ------------------------------------------------------ |
| `rate`             | `number` (0 to 1)        | `1`       | Fraction of entries kept.                              |
| `perLevel`         | `Record<string, number>` | none      | Per-level rates; `'*'` sets a fallback.                |
| `maxLogsPerSecond` | `number`                 | unlimited | Hard cap; `error`, `warn` and `fatal` are exempt.      |
| `traceConsistent`  | `boolean`                | `false`   | Keep or drop all entries of a trace together.          |
| `statsIntervalMs`  | `number`                 | `60000`   | Interval for the sampling stats line; `0` disables it. |
| `adaptive`         | `AdaptiveSamplingConfig` | none      | Boost the rate when the error rate rises.              |

See [Sampling](/guide/sampling).

## `transports`

| Key         | Type                                                  | Description                                                                              |
| ----------- | ----------------------------------------------------- | ---------------------------------------------------------------------------------------- |
| `console`   | `ConsoleTransportConfig`                              | Console output.                                                                          |
| `file`      | `FileTransportConfig` or an array                     | Log files with rotation.                                                                 |
| `database`  | `DatabaseTransportConfig` or an array                 | PostgreSQL, MySQL, MongoDB or SQLite.                                                    |
| `analytics` | `{ mixpanel?, datadog?, googleAnalytics?, segment? }` | Analytics and observability services.                                                    |
| `custom`    | `ITransport[]`                                        | Any transport instance, including the cloud, OTLP, Slack, Discord and worker transports. |

See the [transports overview](/guide/transports/).

## Environment variables

| Variable                    | Effect                                                                                                                                    |
| --------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `LOGIXIA_LEVEL`             | Overrides the configured level for the whole process.                                                                                     |
| `LOGIXIA_LEVEL_<NAMESPACE>` | Overrides the level for loggers whose context's first dot-separated segment matches (`db` and `db.queries` both read `LOGIXIA_LEVEL_DB`). |
| `NODE_ENV`, `CI`            | Choose a default level when `levelOptions` has no `level` (see [Log levels](/guide/log-levels)).                                          |
| `LOGIXIA_SILENT_INTERNAL=1` | Silences logixia's own stderr diagnostics, for example in tests.                                                                          |
