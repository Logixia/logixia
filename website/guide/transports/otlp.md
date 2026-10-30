---
title: OTLP Logs Transport
description: Export logixia logs as OTLP/HTTP JSON to an OpenTelemetry Collector, Grafana Loki, Axiom or Better Stack, with trace ID correlation and severity mapping.
order: 9
---

# OTLP Logs Transport

`OtlpLogTransport` posts logs as **OTLP/HTTP with a JSON body** (`Content-Type: application/json`). It builds the payload itself, so you do not need any `@opentelemetry/*` package. Only the endpoint URL and the auth headers differ between backends.

It is exported from both `logixia` and `logixia/transports`, and you add it through `transports.custom`.

## Quick start

```ts
import { createLogger, OtlpLogTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    custom: [
      new OtlpLogTransport({
        url: 'http://localhost:4318/v1/logs',
        serviceName: 'api',
        serviceVersion: '1.4.0',
        environment: 'production',
      }),
    ],
  },
});

await logger.info('Hello from OTLP');
await logger.close();
```

## Options

| Option               | Type                                          | Default     | Description                                                                                                                |
| -------------------- | --------------------------------------------- | ----------- | -------------------------------------------------------------------------------------------------------------------------- |
| `url`                | `string`                                      | required    | Full OTLP/HTTP logs endpoint, for example `http://localhost:4318/v1/logs`. Used as given: logixia does not add `/v1/logs`. |
| `headers`            | `Record<string, string>`                      | `{}`        | Extra HTTP headers for auth, tenant and so on.                                                                             |
| `serviceName`        | `string`                                      | `'logixia'` | `service.name` resource attribute.                                                                                         |
| `serviceVersion`     | `string`                                      | unset       | `service.version` resource attribute.                                                                                      |
| `environment`        | `string`                                      | unset       | `deployment.environment` resource attribute.                                                                               |
| `resourceAttributes` | `Record<string, string \| number \| boolean>` | unset       | Extra resource attributes merged into the OTLP resource.                                                                   |
| `batchSize`          | `number`                                      | `100`       | Entries per batch and per POST.                                                                                            |
| `flushIntervalMs`    | `number`                                      | `5000`      | Send whatever is buffered after this many ms.                                                                              |
| `requestTimeoutMs`   | `number`                                      | `10000`     | Abort a request that has not finished after this many ms.                                                                  |
| `maxBufferSize`      | `number`                                      | `10000`     | Most buffered entries; the oldest are dropped past this.                                                                   |
| `level`              | `string`                                      | unset       | Minimum level to forward.                                                                                                  |

::: tip
The transport uses the global `fetch`, which exists on Node.js 18 and later. If `fetch` is missing, it warns and skips the export.
:::

## How an entry maps to OTLP

| logixia entry | OTLP log record                                                                                                    |
| ------------- | ------------------------------------------------------------------------------------------------------------------ |
| `timestamp`   | `timeUnixNano` and `observedTimeUnixNano`                                                                          |
| `level`       | `severityNumber` and `severityText` (see below)                                                                    |
| `message`     | `body.stringValue`                                                                                                 |
| payload keys  | `attributes`                                                                                                       |
| `context`     | `context` attribute                                                                                                |
| `appName`     | `app.name` attribute                                                                                               |
| `environment` | `deployment.environment` attribute                                                                                 |
| `traceId`     | `traceId` when it is 32 hex characters (dashes are removed and it is lowercased); otherwise a `trace_id` attribute |

Attribute values are typed: strings, booleans, integers and doubles keep their type. Objects and arrays become JSON strings. The scope name is `logixia`.

A payload field named `spanId` stays a plain attribute. It is not copied into the record's `spanId`.

### Severity mapping

| logixia level      | `severityNumber` | `severityText` |
| ------------------ | ---------------- | -------------- |
| `trace`            | 1                | `TRACE`        |
| `debug`, `verbose` | 5                | `DEBUG`        |
| `info`             | 9                | `INFO`         |
| `warn`, `warning`  | 13               | `WARN`         |
| `error`            | 17               | `ERROR`        |
| `fatal`            | 21               | `FATAL`        |
| anything else      | 9                | `INFO`         |

## Failure handling

A failed batch goes back to the front of the buffer, and threshold-triggered flushes pause for 1 s, doubling up to 30 s. HTTP 4xx responses other than 429 are treated as permanent: the batch is dropped with a warning. The buffer is capped by `maxBufferSize`, dropping the oldest first. `close()` waits for any request in flight, then tries up to three more flushes and reports what is left.

## Backend recipes

The URLs and header names below come from each vendor's documentation (linked per section). Their docs often use placeholders for host names, so copy the real value from your own account.

::: warning JSON support
None of the vendor pages below state whether their logs endpoint accepts OTLP/HTTP JSON (they show protobuf SDKs and Collector examples). If a backend rejects the JSON body, send to a local OpenTelemetry Collector (first recipe) and let the Collector forward in protobuf.
:::

### Local OpenTelemetry Collector

`otel-collector.yaml`, which prints every log record to stdout:

```yaml
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318

exporters:
  debug:
    verbosity: detailed

service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [debug]
```

Run it with `docker run --rm -p 4318:4318 -v "$PWD/otel-collector.yaml:/etc/otelcol-contrib/config.yaml" otel/opentelemetry-collector-contrib`, then:

```ts
import { createLogger, OtlpLogTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    custom: [
      new OtlpLogTransport({
        url: 'http://localhost:4318/v1/logs',
        serviceName: 'api',
        environment: 'development',
      }),
    ],
  },
});
```

Docs: [OTLP receiver](https://github.com/open-telemetry/opentelemetry-collector/tree/main/receiver/otlpreceiver), [debug exporter](https://github.com/open-telemetry/opentelemetry-collector/tree/main/exporter/debugexporter).

### Grafana Loki

Loki 3.x accepts OTLP natively at `POST /otlp/v1/logs`. The transport needs the full URL: Loki's docs say a Collector `otlphttp` exporter takes only `http://<LOKI_ADDR>/otlp`, but this transport does not append `/v1/logs` for you.

```ts
import { OtlpLogTransport } from 'logixia';

export const loki = new OtlpLogTransport({
  url: 'http://loki:3100/otlp/v1/logs',
  serviceName: 'api',
});
```

Self-hosted Loki with multi-tenancy also needs the usual `X-Scope-OrgID` tenant header.

**Grafana Cloud** uses the OTLP gateway with Basic auth. Copy the endpoint and credentials from the **OpenTelemetry** tile of your stack: the endpoint looks like `https://otlp-gateway-<REGION>.grafana.net/otlp`, and the logs URL is that plus `/v1/logs`. Grafana's docs do not spell out which half of the Basic credential is which, so use what the tile generates (in practice the instance ID and the access token).

```ts
import { OtlpLogTransport } from 'logixia';

const basic = Buffer.from(
  `${process.env.GRAFANA_INSTANCE_ID}:${process.env.GRAFANA_TOKEN}`
).toString('base64');

export const grafanaCloud = new OtlpLogTransport({
  url: 'https://otlp-gateway-<REGION>.grafana.net/otlp/v1/logs',
  headers: { Authorization: `Basic ${basic}` },
  serviceName: 'api',
});
```

Docs: [Loki OTLP ingestion](https://grafana.com/docs/loki/latest/send-data/otel/), [Loki HTTP API](https://grafana.com/docs/loki/latest/reference/loki-http-api/), [Grafana Cloud OTLP](https://grafana.com/docs/grafana-cloud/send-data/otlp/send-data-otlp/).

### Axiom

Endpoint `https://AXIOM_DOMAIN/v1/logs`, where `AXIOM_DOMAIN` is the base domain of your edge deployment (see Axiom's edge deployments page). Headers: `Authorization: Bearer <API token with ingest permission>` and `X-Axiom-Dataset: <dataset>`. Use a dedicated dataset created with the **Events** option.

```ts
import { OtlpLogTransport } from 'logixia';

export const axiom = new OtlpLogTransport({
  url: `https://${process.env.AXIOM_DOMAIN}/v1/logs`,
  headers: {
    Authorization: `Bearer ${process.env.AXIOM_TOKEN}`,
    'X-Axiom-Dataset': process.env.AXIOM_DATASET!,
  },
  serviceName: 'api',
});
```

Docs: [Axiom OpenTelemetry](https://axiom.co/docs/send-data/opentelemetry).

### Better Stack

Endpoint `https://<INGESTING_HOST>/v1/logs` with `Authorization: Bearer <source token>`. The ingesting host and source token are shown on your source's page in Better Stack.

```ts
import { OtlpLogTransport } from 'logixia';

export const betterStack = new OtlpLogTransport({
  url: `https://${process.env.BETTERSTACK_INGESTING_HOST}/v1/logs`,
  headers: { Authorization: `Bearer ${process.env.BETTERSTACK_SOURCE_TOKEN}` },
  serviceName: 'api',
});
```

Docs: [Better Stack OpenTelemetry](https://betterstack.com/docs/logs/open-telemetry/).

## Related

- [OpenTelemetry](/guide/opentelemetry) for reading the active span into your logs
- [Tracing](/guide/tracing)
- [Transports overview](/guide/transports/)
