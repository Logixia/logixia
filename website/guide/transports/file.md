---
title: File Transport
description: Write logixia logs to files with size, date and interval rotation, gzip archives, retention, JSON, text or CSV formats, and a bounded in-memory queue.
order: 3
---

# File Transport

The file transport appends entries to a local file, rotates it by size, date or interval, optionally gzips old files, and prunes the oldest. It needs no extra packages.

## Quick start

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    file: {
      filename: 'app.log',
      dirname: './logs',
      maxSize: '50MB',
      maxFiles: 14,
      zippedArchive: true,
    },
  },
});

await logger.info('Server started', { port: 3000 });
await logger.close();
```

The live file keeps its name (`logs/app.log`), so `tail -f` keeps working. Rotated files are renamed beside it, for example `app-2026-10-22T09-30-00-000.log.gz`.

## Options

| Option          | Type                                        | Default                                                           | Description                                                                                                                                 |
| --------------- | ------------------------------------------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------- |
| `filename`      | `string`                                    | required                                                          | File name, or a path if `dirname` is not set.                                                                                               |
| `dirname`       | `string`                                    | directory of `filename`, or the current directory for a bare name | Directory for log files. Created if missing.                                                                                                |
| `format`        | `'json' \| 'text' \| 'csv'`                 | `'json'`                                                          | Line format. See [Formats](#formats).                                                                                                       |
| `maxSize`       | `string \| number`                          | unset                                                             | Rotate before the file would pass this size. Bytes, or a string such as `'500KB'`, `'50MB'`, `'1GB'`. Units are binary (1KB is 1024 bytes). |
| `maxFiles`      | `number`                                    | unset                                                             | Keep this many rotated files and delete older ones. Unset keeps all.                                                                        |
| `datePattern`   | `string`                                    | unset                                                             | Rotate when the formatted date changes. Tokens: `YYYY`, `MM`, `DD`, `HH`, `mm`, `ss`, in local time.                                        |
| `zippedArchive` | `boolean`                                   | `false`                                                           | Gzip rotated files to `<file>.gz`.                                                                                                          |
| `rotation`      | `RotationConfig`                            | unset                                                             | Interval rotation and a custom check. See [Interval rotation](#interval-rotation).                                                          |
| `batchSize`     | `number`                                    | `100`                                                             | Entries to collect before writing. `1` writes every entry straight away.                                                                    |
| `flushInterval` | `number` (ms)                               | `5000`                                                            | Write whatever is buffered after this long.                                                                                                 |
| `maxQueue`      | `number`                                    | `10000`                                                           | Most entries held in memory that are not on disk yet.                                                                                       |
| `queuePolicy`   | `'drop-oldest' \| 'drop-newest' \| 'block'` | `'drop-oldest'`                                                   | What to do when `maxQueue` is reached.                                                                                                      |
| `fileMode`      | `number`                                    | `0o600`                                                           | Permission bits for log files, rotated and gzipped ones included.                                                                           |
| `dirMode`       | `number`                                    | `0o700`                                                           | Permission bits for directories the transport creates.                                                                                      |
| `level`         | `string`                                    | unset                                                             | Minimum level for this transport.                                                                                                           |
| `filter`        | `(entry) => boolean`                        | unset                                                             | Return `false` to skip an entry on this transport.                                                                                          |

An invalid `maxSize` (not a number or a string like `'50MB'`) is reported on stderr and size rotation stays off. An invalid `maxQueue` falls back to 10,000 with a warning.

## Formats

**`json`** writes one object per line with `timestamp`, `level`, `message` and then your payload keys. If a payload key matches a core name, it is kept under a `data_` prefix.

**`text`** writes `2026-10-22T09:30:00.000Z [INFO] message {"key":"value"}`. The payload is appended as JSON when present.

**`csv`** writes six columns with no header row: timestamp, level, message, context, trace ID and the payload as JSON. Fields other than the timestamp are double-quoted with inner quotes doubled.

::: tip
The `json` and `text` formats do not write `context`, `traceId`, `appName` or `environment` as fields. If you need the trace ID in the file, use `csv`, or include it in the payload you log.
:::

## Rotation

### By size

With `maxSize` set, a batch is split on line boundaries so no line is cut in half and no file grows past the limit, unless a single line is bigger than `maxSize` on its own. When the transport starts it reads the size of the existing file, so a restart next to a 49MB `app.log` still rotates at 50MB.

### By date

`datePattern: 'YYYY-MM-DD'` rotates when the day changes, and `'YYYY-MM-DD-HH'` rotates hourly. The archived file is named after the period it covers, for example `app-2026-10-22.log`. You can combine `datePattern` with `maxSize`.

### Interval rotation

Use the `rotation` block for interval-based rotation or your own check:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    file: {
      filename: 'app.log',
      dirname: './logs',
      rotation: {
        interval: '1d',
        maxSize: '100MB',
        maxFiles: 30,
        compress: true,
        shouldRotate: (_file, stats) => stats.size > 100 * 1024 * 1024,
      },
    },
  },
});
```

| `rotation` option | Type                                                    | Description                                                                                           |
| ----------------- | ------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| `interval`        | `'1h' \| '6h' \| '12h' \| '1d' \| '1w' \| '1m' \| '1y'` | Rotate after this much time since the last rotation (or since the process started).                   |
| `maxSize`         | `string \| number`                                      | Same as the top-level `maxSize`; takes precedence over it.                                            |
| `maxFiles`        | `number`                                                | Same as the top-level `maxFiles`; takes precedence.                                                   |
| `compress`        | `boolean`                                               | Same as `zippedArchive`; takes precedence.                                                            |
| `shouldRotate`    | `(currentFile, stats) => boolean`                       | Checked before each write. Return `true` to rotate now. `stats` has `size`, `created` and `modified`. |

::: warning
In `interval`, `m` means 30 days, not minutes, and `y` means 365 days. An interval string logixia cannot parse falls back to one day.
:::

::: warning
With a `rotation` block, every file is timestamped, the live one included. Without it, the live file keeps its plain name.
:::

### Retention and gzip

Only files that look like this transport's own rotations are counted for `maxFiles` (the base name, a dash, a stamp of digits and separators, optionally `.gz`). A neighbouring `app-error.log` is never deleted by `app.log`'s retention. Gzip and pruning run off the write path, one at a time, and a failed gzip leaves the original file in place.

## Bounded memory

Entries wait in memory until the disk accepts them. `maxQueue` (default 10,000) caps how many can wait, the batch being written included. `queuePolicy` decides what happens at the cap:

| Policy        | Effect                                                                              |
| ------------- | ----------------------------------------------------------------------------------- |
| `drop-oldest` | Discards the oldest waiting entry to make room.                                     |
| `drop-newest` | Discards the incoming entry.                                                        |
| `block`       | `write()` waits until there is room, which slows the caller instead of losing logs. |

Dropped entries are counted and reported on stderr at most once every 5 seconds, and once more on `close()`.

## Multiple files

Pass an array to write to several files. Combine it with `level` or `filter` to split output.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    file: [
      { filename: 'app.log', dirname: './logs', format: 'json' },
      { filename: 'error.log', dirname: './logs', format: 'json', level: 'error' },
    ],
  },
});
```

## Using the class directly

`FileTransport` also has `flush()`, which resolves once everything queued before the call is on disk, and `rotate()`, which writes out what is pending and starts a new file.

```ts
import { FileTransport } from 'logixia/transports';

const transport = new FileTransport({ filename: 'app.log', dirname: './logs', batchSize: 1 });

await transport.write({ timestamp: new Date(), level: 'info', message: 'hello' });
await transport.rotate();
await transport.close();
```

## Related

- [Console transport](/guide/transports/console)
- [Worker thread transport](/guide/transports/worker) to move file I/O off the main thread
- [Graceful shutdown](/guide/graceful-shutdown) so buffered lines are written on exit
