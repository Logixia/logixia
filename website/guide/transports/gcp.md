---
title: Google Cloud Logging Transport
description: Send logixia logs to Google Cloud Logging with severity mapping, Cloud Trace correlation, monitored resources, metadata-server auth and service account keys.
order: 6
---

# Google Cloud Logging Transport

`GCPTransport` batches entries and writes them to the Cloud Logging `entries:write` API over HTTPS. It maps logixia levels to GCP severities and adds a trace field for correlation with Cloud Trace. No Google client library is needed.

## Quick start

Import it from `logixia/gcp` and put an instance in `transports.custom`.

```ts
import { createLogger } from 'logixia';
import { GCPTransport } from 'logixia/gcp';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [
      new GCPTransport({
        projectId: 'my-gcp-project',
        logName: 'projects/my-gcp-project/logs/api',
        resource: { type: 'k8s_container', labels: { cluster_name: 'prod' } },
      }),
    ],
  },
});

await logger.error('Upstream timed out', { upstream: 'billing' });
await logger.close();
```

## Options

| Option             | Type                                                | Default                                                                 | Description                                                                  |
| ------------------ | --------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `projectId`        | `string`                                            | `GOOGLE_CLOUD_PROJECT`, then `GCLOUD_PROJECT`, then `'unknown-project'` | GCP project ID.                                                              |
| `logName`          | `string`                                            | `projects/<projectId>/logs/logixia`                                     | Full log name.                                                               |
| `resource`         | `{ type: string; labels?: Record<string, string> }` | `{ type: 'global' }`                                                    | Monitored resource descriptor.                                               |
| `credentials`      | `{ client_email: string; private_key: string }`     | none                                                                    | Service account key, parsed. Used when the metadata server is not available. |
| `batchSize`        | `number`                                            | `200`                                                                   | Entries per request.                                                         |
| `flushIntervalMs`  | `number`                                            | `5000`                                                                  | Send whatever is buffered after this many ms.                                |
| `requestTimeoutMs` | `number`                                            | `10000`                                                                 | Abort a request that has not finished after this many ms.                    |
| `maxBufferSize`    | `number`                                            | `10000`                                                                 | Most buffered entries; the oldest are dropped past this.                     |
| `level`            | `string`                                            | unset                                                                   | Minimum level to forward.                                                    |

## Authentication

The transport asks for an access token in this order:

1. The GCE, GKE and Cloud Run metadata server (`metadata.google.internal`), with a 3 second timeout. The token is cached for 55 minutes.
2. The service account in `credentials`, using a signed JWT exchanged at `oauth2.googleapis.com`.

If neither gives a token, the batch stays buffered and the write is retried later.

::: warning
The `GOOGLE_APPLICATION_CREDENTIALS` environment variable is not read. Outside Google-hosted infrastructure, pass `credentials` yourself, for example from a secret manager, rather than relying on a key file path.
:::

## Severity mapping

| logixia level               | GCP severity |
| --------------------------- | ------------ |
| `trace`, `verbose`, `debug` | `DEBUG`      |
| `info`, `log`               | `INFO`       |
| `warn`, `warning`           | `WARNING`    |
| `error`                     | `ERROR`      |
| `critical`, `fatal`         | `CRITICAL`   |
| anything else               | `DEFAULT`    |

## What is sent

Each entry becomes a Cloud Logging `LogEntry` with:

- `severity` from the table above and the `timestamp` of the entry.
- `jsonPayload` with `message`, `appName`, `context` and your payload keys. A payload key that clashes with one of those names is stored with a `data_` prefix.
- `trace` set to `projects/<projectId>/traces/<traceId>` and `traceSampled: true` when the entry has a trace ID, so the log shows up next to the trace in the console.

## Failure handling

The transport uses the same buffering as the other HTTP transports. A failed request puts the batch back at the front of the buffer and pauses threshold-triggered flushes for 1 s, doubling up to 30 s. HTTP 4xx responses other than 429 drop the batch with a warning. The buffer is capped by `maxBufferSize`, dropping the oldest first. `close()` flushes up to three times and reports anything undelivered.

## Related

- [Transports overview](/guide/transports/)
- [OpenTelemetry](/guide/opentelemetry) and [Tracing](/guide/tracing) for trace IDs
- [CloudWatch transport](/guide/transports/cloudwatch) and [Azure transport](/guide/transports/azure)
