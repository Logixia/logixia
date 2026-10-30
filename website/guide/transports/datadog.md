---
title: Datadog Transport
description: Ship logixia logs to Datadog with the v2 Logs intake, regional sites, optional gzip, status mapping, trace correlation through dd.trace_id and optional metrics.
order: 8
---

# Datadog Transport

`DataDogTransport` sends batches of entries to the Datadog Logs HTTP intake (v2), and can also send a count metric per entry. The API key goes in the `DD-API-KEY` header, never in the URL.

It is one of the analytics transports, so you configure it under `transports.analytics.datadog`. Its class is exported from `logixia/transports`.

## Quick start

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    analytics: {
      datadog: {
        apiKey: process.env.DD_API_KEY!,
        site: 'datadoghq.eu',
        service: 'api',
        env: 'production',
        version: '1.4.0',
        compress: true,
      },
    },
  },
});

await logger.error('Checkout failed', { orderId: 'o_1' });
await logger.close();
```

## Options

| Option             | Type                                                                                                                       | Default           | Description                                                                                             |
| ------------------ | -------------------------------------------------------------------------------------------------------------------------- | ----------------- | ------------------------------------------------------------------------------------------------------- |
| `apiKey`           | `string`                                                                                                                   | required          | Datadog API key. If it is empty, every write fails with "DataDog API key is required".                  |
| `site`             | `'datadoghq.com' \| 'datadoghq.eu' \| 'us3.datadoghq.com' \| 'us5.datadoghq.com' \| 'ap1.datadoghq.com' \| 'ddog-gov.com'` | `'datadoghq.com'` | Datadog site. Logs go to `https://http-intake.logs.<site>`, metrics and events to `https://api.<site>`. |
| `service`          | `string`                                                                                                                   | `'logixia'`       | `service` attribute and tag.                                                                            |
| `env`              | `string`                                                                                                                   | `'production'`    | `env` attribute and tag.                                                                                |
| `version`          | `string`                                                                                                                   | unset             | `version` attribute and tag.                                                                            |
| `compress`         | `boolean`                                                                                                                  | `false`           | Gzip log request bodies (`Content-Encoding: gzip`).                                                     |
| `enableLogs`       | `boolean`                                                                                                                  | on                | Send logs. Only an explicit `false` turns it off.                                                       |
| `enableMetrics`    | `boolean`                                                                                                                  | off               | Also send a count metric per entry.                                                                     |
| `batchSize`        | `number`                                                                                                                   | `50`              | Entries collected before a send.                                                                        |
| `flushInterval`    | `number` (ms)                                                                                                              | `10000`           | Send whatever is buffered after this long.                                                              |
| `maxBufferSize`    | `number`                                                                                                                   | `10000`           | Most entries held while Datadog is unreachable. Never below `batchSize`.                                |
| `customProperties` | `Record<string, unknown>`                                                                                                  | unset             | Extra attributes merged into every log. They are applied last and win over payload keys.                |
| `level`            | `string`                                                                                                                   | unset             | Minimum level for this transport.                                                                       |
| `filter`           | `(entry) => boolean`                                                                                                       | unset             | Return `false` to skip an entry on this transport.                                                      |
| `enableTraces`     | `boolean`                                                                                                                  | none              | Deprecated, has no effect. Trace correlation is always added.                                           |

::: warning
Entries with level `debug` or `trace` are never sent to Datadog (or to the other analytics providers). Use `info` and above for what you want in Datadog, and send `debug` logs to a file or OTLP.
:::

## What is sent

Each log has these top-level attributes:

| Attribute                                                            | Value                                                                                                                                                      |
| -------------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `ddsource`                                                           | `'nodejs'`                                                                                                                                                 |
| `ddtags`                                                             | `env:<env>,service:<service>` plus `version:<version>` when set. Tags are lowercased, commas and whitespace become `_`, and each is cut to 200 characters. |
| `hostname`                                                           | The machine host name                                                                                                                                      |
| `service`, `env`, `version`                                          | From the config                                                                                                                                            |
| `status`                                                             | Mapped from the level (see below)                                                                                                                          |
| `message`                                                            | The message                                                                                                                                                |
| `logger`                                                             | `{ name: 'logixia', thread_name: 'main' }`                                                                                                                 |
| `timestamp`, `level`, `context`, `traceId`, `appName`, `environment` | From the entry, when present                                                                                                                               |
| `dd.trace_id`, `dd.span_id`                                          | Trace correlation (see below)                                                                                                                              |

Your payload keys are added as extra attributes. If a payload key clashes with a core field or a Datadog reserved name (`status`, `ddtags`, `ddsource`, `hostname`, `host`, `source`, `service`, `version`, `env`, `logger`, `dd.trace_id`, `dd.span_id`), it is stored under a `data_` prefix, so a user field can never overwrite those.

### Status mapping

| logixia level               | Datadog `status` |
| --------------------------- | ---------------- |
| `fatal`, `critical`         | `critical`       |
| `error`                     | `error`          |
| `warn`, `warning`           | `warn`           |
| `info`                      | `info`           |
| `debug`, `trace`, `verbose` | `debug`          |
| anything else               | `info`           |

### Trace correlation with `dd.trace_id`

Datadog correlates logs and traces on a decimal 64-bit ID. logixia converts the entry's trace ID for you:

- A dashed UUID (logixia's default trace ID) has its dashes removed and is then treated as 32 hex characters.
- 32 hex characters (a W3C trace ID), or 16 hex characters, use the low 64 bits as a decimal number.
- An all-digit string is taken as already decimal (what `dd-trace` uses) and passed through if it fits in 64 bits. A 32-digit string is read as hex, and a 16-digit string as decimal.
- Anything else is sent as it is.

If the payload has `spanId` or `span_id`, it is converted the same way into `dd.span_id`, and only when there is a trace ID too. This is what lets the Datadog UI link a log to its trace. See [OpenTelemetry](/guide/opentelemetry) for how span IDs reach your payload.

## Batching, limits and failures

- A request carries at most 1,000 logs and about 5 MB. Bigger batches are split into several requests, in order.
- A single log over 1 MB is cut down: it keeps its identity and correlation fields, its message is cut to 150,000 characters, its other attributes are dropped, and `truncated: true` is added.
- If a request fails, the entries from that request onward stay in the buffer and are sent on the next flush. Chunks Datadog already accepted are not sent twice.
- Any non-2xx response counts as a failure and is retried later. The buffer is capped by `maxBufferSize`, dropping the oldest first.
- `close()` tries up to three flushes, then reports anything undelivered.

## Metrics

With `enableMetrics: true`, each entry also posts a count of 1 to `/api/v1/series`, named `logitron.logs.<level>`, with tags for `level`, `service`, `env`, `context` and `app`. The `logitron.` prefix is kept so existing dashboards keep working.

If metrics fail after the logs were delivered, the logs are not re-sent. Turn off logs with `enableLogs: false` to send metrics only.

## Extra helpers

If you create the transport yourself, two extra methods are available: `sendCustomMetric({ name, value, tags?, timestamp? })` posts a gauge, and `sendEvent(title, text, tags?)` posts a Datadog event.

```ts
import { createLogger } from 'logixia';
import { DataDogTransport } from 'logixia/transports';

const datadog = new DataDogTransport({
  apiKey: process.env.DD_API_KEY!,
  service: 'api',
  enableMetrics: true,
});

const logger = createLogger({
  appName: 'api',
  transports: { custom: [datadog] },
});

await datadog.sendCustomMetric({ name: 'queue.depth', value: 42, tags: { queue: 'emails' } });
await datadog.sendEvent('Deploy finished', 'api 1.4.0 is live', ['team:platform']);
await logger.info('Started');
await logger.close();
```

## Related

- [Analytics transports](/guide/transports/analytics)
- [OTLP transport](/guide/transports/otlp) if you prefer to send logs to Datadog through an OpenTelemetry Collector
- [Tracing](/guide/tracing)
