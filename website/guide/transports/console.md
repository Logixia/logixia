---
title: Console Transport
description: Configure the logixia console transport for colored text or compact JSON output on stdout and stderr, with custom level colors, timestamps and filters.
order: 2
---

# Console Transport

The console transport prints each entry to the terminal. `warn` and `error` go to stderr, everything else goes to stdout. It writes synchronously, so it never allocates a promise on the hot path.

Import `ConsoleTransport` from `logixia/transports` if you need the class. Most of the time you just set `transports.console`.

## Quick start

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    console: { format: 'text', colorize: true },
  },
});

await logger.info('Server started', { port: 3000 });
```

Text output looks like this: a gray timestamp, the level padded to 5 characters, the context in brackets, the trace ID in parentheses, the message, then the payload as JSON.

## JSON output

Set `format: 'json'` for one compact JSON object per line, which is what log collectors in containers expect.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    console: { format: 'json' },
  },
});

await logger.info('Order placed', { orderId: 'o_1' });
```

The JSON object has `timestamp`, `level`, `message`, `context`, `traceId`, `appName` and `environment`, followed by your payload keys. If a payload key clashes with one of those names, logixia keeps the core field and stores your value under a `data_` prefix, for example `data_level`.

## Options

| Option        | Type                     | Default  | Description                                             |
| ------------- | ------------------------ | -------- | ------------------------------------------------------- |
| `format`      | `'json' \| 'text'`       | `'text'` | Pretty text or one JSON object per line.                |
| `colorize`    | `boolean`                | on       | ANSI colors in text mode. Set `false` to turn them off. |
| `timestamp`   | `boolean`                | on       | Include the ISO timestamp. Set `false` to drop it.      |
| `levelColors` | `Record<string, string>` | none     | Level name to color name. See below.                    |
| `filter`      | `(entry) => boolean`     | none     | Return `false` to skip an entry on this transport.      |
| `level`       | `string`                 | none     | Declared in the type, but see the warning below.        |

::: warning
The console transport does not apply `level`. Setting `transports.console.level` has no effect today. To change what reaches the console, set the logger's global `levelOptions.level`, or use `filter`:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    console: { filter: (entry) => entry.level !== 'debug' },
  },
});
```

:::

## Level colors

Built-in colors are `error` red, `warn` and `warning` yellow, `info` green, `debug` blue, `trace` magenta and `verbose` cyan. Anything else is gray.

For custom levels, set `levelOptions.colors` on the logger. logixia passes that map to the console transport as `levelColors` for you.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  levelOptions: {
    level: 'info',
    levels: { error: 0, warn: 1, info: 2, kafka: 2 },
    colors: { kafka: 'magenta' },
  },
  transports: { console: {} },
});

await logger.kafka('Consumer joined group');
```

Color names are `black`, `red`, `green`, `yellow`, `blue`, `magenta`, `cyan`, `white`, `gray`, `grey` and the `bright` variants (`brightred`, `brightgreen`, and so on).

## Safe by default

In text mode, control characters are stripped from the level, context, trace ID and message, so a hostile string cannot inject ANSI escapes or fake log lines into your terminal. Payloads are serialized with a cycle-safe `JSON.stringify`, which already escapes control characters.

## Related

- [Configuration](/guide/configuration) for logger-level `format` and level options
- [Log levels](/guide/log-levels) for custom levels and colors
- [File transport](/guide/transports/file) to also keep logs on disk
