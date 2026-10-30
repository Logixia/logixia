---
title: Sampling and rate limiting
description: Cut log volume with logixia sampling - global and per-level rates, trace-consistent sampling, a per-second cap and adaptive boosting when errors spike.
order: 10
---

# Sampling and rate limiting

`sampling` drops a share of entries before they reach transports. Use it when debug or info volume is high and you want to keep cost down without losing errors.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  sampling: {
    rate: 0.1,
    perLevel: { debug: 0.01, info: 0.25 },
    maxLogsPerSecond: 500,
    traceConsistent: true,
    statsIntervalMs: 0,
  },
});

await logger.info('request handled');
```

## Options

| Option             | Type                     | Default   | Description                                                           |
| ------------------ | ------------------------ | --------- | --------------------------------------------------------------------- |
| `rate`             | `number`, 0 to 1         | `1`       | Fraction of entries kept. `1` keeps all, `0` drops all.               |
| `perLevel`         | `Record<string, number>` | none      | Per-level rates. `'*'` is a fallback for levels not listed.           |
| `maxLogsPerSecond` | `number`                 | unlimited | Hard cap on kept entries per second, applied after the rate decision. |
| `traceConsistent`  | `boolean`                | `false`   | Keep or drop all entries of one trace together.                       |
| `statsIntervalMs`  | `number`                 | `60000`   | How often the stats line is written. `0` disables it.                 |
| `adaptive`         | `AdaptiveSamplingConfig` | none      | Raise the rate when the error rate spikes.                            |

The rate for an entry is `perLevel[level]`, else `perLevel['*']`, else `rate`.

## What is never sampled

`error`, `warn` and `fatal` entries are always kept, and are exempt from `maxLogsPerSecond`, unless you give that level an explicit `perLevel` value. To sample warnings, set `perLevel: { warn: 0.5 }`.

## Trace-consistent sampling

Without `traceConsistent`, each entry is sampled independently, so a trace can end up with missing lines. With it, the first decision for a trace ID is remembered and applied to every later entry of that trace. Entries with no trace are sampled individually.

Decisions are kept in a bounded cache (100,000 traces, an idle expiry of five minutes and a one-hour maximum lifetime). IDs that are empty, too long or contain control characters are sampled independently and not cached.

## Per-second cap

`maxLogsPerSecond` is a token bucket that refills continuously. Entries kept by the rate decision but beyond the cap are dropped and counted. It also applies with `traceConsistent`.

## Adaptive sampling

Adaptive sampling captures an incident in full while keeping the steady-state rate low:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  sampling: {
    rate: 0.05,
    adaptive: { errorRateThreshold: 0.05, boostRate: 1, windowMs: 10_000, minSamples: 20 },
  },
});

await logger.info('ready');
```

| Option               | Default | Description                                                     |
| -------------------- | ------- | --------------------------------------------------------------- |
| `errorRateThreshold` | `0.05`  | Share of recent entries that must be errors to trigger a boost. |
| `boostRate`          | `1`     | Rate used while boosted.                                        |
| `windowMs`           | `10000` | Size of the sliding window.                                     |
| `minSamples`         | `20`    | Entries needed in the window before the error rate is trusted.  |

While boosted, the effective rate is the higher of the normal rate and `boostRate`.

## The stats line

With sampling configured, logixia writes a JSON line directly to stdout every `statsIntervalMs` (60 seconds by default):

```json
{
  "level": "info",
  "message": "[logixia/sampling] stats",
  "evaluated": 1200,
  "emitted": 130,
  "dropped": 1070,
  "byLevel": { "info": { "evaluated": 1100, "emitted": 110 } },
  "windowStart": 1767000000000
}
```

This line bypasses transports and formatting, so it appears on stdout even if you only configured a file transport. Set `statsIntervalMs: 0` to turn it off. The counters reset after each report.

::: tip Sampling and metrics
Sampling happens before plugins run, so [metrics](/guide/metrics) derived from logs count only sampled entries. If you need accurate counts, extract metrics from a logger that is not sampled, or sample only the levels you do not count.
:::

`SamplingStats` is exported as a type for code that handles these numbers.
