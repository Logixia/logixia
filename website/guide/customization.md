---
title: Customizing output
description: Customize logixia output - level colors, custom levels, which fields appear, JSON or text format, and per-environment setups for development and production.
order: 20
---

# Customizing output

This page collects the options that change how entries look: level colors, visible fields and format. For where entries go, see [Transports](/guide/transports/). For the full option list, see [Configuration](/guide/configuration).

::: tip Two output paths
`fields` and the logger-level `format` apply only when you have not set `transports`. Once you set `transports`, format each transport instead (for example `transports.console.format`). See [Configuration](/guide/configuration).
:::

## Level colors

Colors are set per level in `levelOptions.colors`. Pass all the levels you care about, because setting `levelOptions` replaces the defaults.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  levelOptions: {
    level: 'debug',
    colors: {
      error: 'brightRed',
      warn: 'brightYellow',
      info: 'brightBlue',
      debug: 'brightGreen',
      trace: 'gray',
      verbose: 'brightCyan',
    },
  },
});

await logger.info('colored by level');
```

Available colors: `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`, `gray`, `grey`, `brightRed`, `brightGreen`, `brightYellow`, `brightBlue`, `brightMagenta`, `brightCyan`, `brightWhite`. Set `format.colorize: false` (default path) or `transports.console.colorize: false` to turn colors off.

Colors set here are also given to the console transport, so custom levels keep their color when you add `transports.console`.

## Custom levels with colors

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  levelOptions: {
    level: 'info',
    levels: { error: 0, warn: 1, critical: 0, audit: 1, notice: 2, info: 2, debug: 3 },
    colors: { critical: 'magenta', audit: 'brightYellow', notice: 'white' },
  },
});

await logger.critical('database unreachable');
await logger.audit('role changed', { userId: 'u_9' });
```

A custom level without a color gets one from a small rotating palette. See [Log levels](/guide/log-levels) for how priorities work.

## Choosing visible fields

In the default output path, `fields` hides parts of the line. A value of `false` hides a field; anything else, or leaving the field out, shows it.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  fields: {
    timestamp: true,
    level: true,
    appName: true,
    traceId: false,
    message: true,
    payload: false,
  },
});

await logger.info('only the essentials', { hidden: true });
```

The fields the text line can show are `timestamp`, `level`, `appName`, `traceId`, `context`, `message` and `payload`. Fields you leave out of `fields` stay visible.

Toggle a field on one logger at runtime:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({ appName: 'api' });

logger.disableField('traceId');
console.log(logger.isFieldEnabled('traceId')); // false
logger.enableField('traceId');
logger.resetFieldState(); // back to the configuration
console.log(logger.getFieldState());
```

Each toggle also prints a short `[logixia]` notice on stderr.

## Text or JSON

On the default path:

```ts
import { createLogger } from 'logixia';

const text = createLogger({ appName: 'api', format: { timestamp: true, colorize: true } });
const json = createLogger({ appName: 'api', format: { json: true, colorize: false } });

await text.info('human readable');
await json.info('one JSON object per line');
```

With transports, use the transport's own `format`:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: { console: { format: process.env['NODE_ENV'] === 'production' ? 'json' : 'text' } },
});

await logger.info('format chosen by environment');
```

## Per-environment setups

```ts
import { createLogger } from 'logixia';

const isProd = process.env['NODE_ENV'] === 'production';

export const logger = createLogger({
  appName: 'api',
  environment: isProd ? 'production' : 'development',
  levelOptions: { level: isProd ? 'warn' : 'debug' },
  redact: isProd ? { autoDetect: true } : {},
  transports: isProd
    ? { file: { filename: 'app.log', dirname: '/var/log/api', format: 'json', maxFiles: 7 } }
    : { console: { format: 'text' } },
});
```

Tips:

- Keep field names consistent across your services, so queries and dashboards work everywhere.
- Prefer a lower level in production and raise it temporarily with `setLevel()` or `LOGIXIA_LEVEL` (see [Log levels](/guide/log-levels)).
- Do not log secrets in the payload; configure [redaction](/guide/redaction).

## Going further

For behaviour that options cannot express, write a [plugin](/guide/plugins) to transform entries or a [custom transport](/guide/transports/custom) to send them somewhere new.
