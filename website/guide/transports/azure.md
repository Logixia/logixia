---
title: Azure Monitor Transport
description: Send logixia logs to Azure Monitor with the Logs Ingestion API and a Data Collection Rule, using OAuth2 client credentials, severity mapping and batching.
order: 7
---

# Azure Monitor Transport

`AzureMonitorTransport` sends batches of entries to the Azure Monitor Logs Ingestion API (a Data Collection Endpoint plus a Data Collection Rule). It gets its own bearer token with the OAuth2 client-credentials flow, so you do not need an Azure SDK.

## Quick start

Import it from `logixia/azure` and put an instance in `transports.custom`.

```ts
import { createLogger } from 'logixia';
import { AzureMonitorTransport } from 'logixia/azure';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [
      new AzureMonitorTransport({
        endpoint: 'https://my-dce.ingest.monitor.azure.com',
        ruleId: process.env.AZURE_DCR_ID!,
        streamName: 'Custom-LogixiaLogs_CL',
        // tenantId, clientId and clientSecret are read from
        // AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET when omitted
      }),
    ],
  },
});

await logger.error('Job failed', { job: 'nightly-sync' });
await logger.close();
```

## Options

| Option             | Type     | Default               | Description                                                                                       |
| ------------------ | -------- | --------------------- | ------------------------------------------------------------------------------------------------- |
| `endpoint`         | `string` | required              | Data Collection Endpoint URL, such as `https://<name>.ingest.monitor.azure.com`. Must be `https`. |
| `ruleId`           | `string` | required              | Data Collection Rule immutable ID.                                                                |
| `streamName`       | `string` | required              | Stream name defined in the rule.                                                                  |
| `tenantId`         | `string` | `AZURE_TENANT_ID`     | Azure AD tenant (a GUID or a verified domain).                                                    |
| `clientId`         | `string` | `AZURE_CLIENT_ID`     | App registration (service principal) client ID.                                                   |
| `clientSecret`     | `string` | `AZURE_CLIENT_SECRET` | Client secret.                                                                                    |
| `batchSize`        | `number` | `200`                 | Entries per request.                                                                              |
| `flushIntervalMs`  | `number` | `5000`                | Send whatever is buffered after this many ms.                                                     |
| `requestTimeoutMs` | `number` | `10000`               | Abort a request that has not finished after this many ms.                                         |
| `maxBufferSize`    | `number` | `10000`               | Most buffered entries; the oldest are dropped past this.                                          |
| `level`            | `string` | unset                 | Minimum level to forward.                                                                         |

If any of tenant, client ID or secret is missing, the transport logs a warning and keeps entries buffered. Managed identity is not supported.

The service principal must be allowed to publish to the Data Collection Rule.

## What is sent

Each entry is posted to `<endpoint>/dataCollectionRules/<ruleId>/streams/<streamName>?api-version=2023-01-01` as a record with these columns, so define a matching stream in your rule:

| Column          | Value                                   |
| --------------- | --------------------------------------- |
| `TimeGenerated` | Entry timestamp                         |
| `SeverityLevel` | See the table below                     |
| `Message`       | Message text                            |
| `AppName`       | `appName`                               |
| `Context`       | Context, or empty string                |
| `TraceId`       | Trace ID, or empty string               |
| `Properties`    | The payload serialized as a JSON string |

| logixia level          | `SeverityLevel` |
| ---------------------- | --------------- |
| `verbose`, `trace`     | 0               |
| `debug`, `info`, `log` | 1               |
| `warn`, `warning`      | 2               |
| `error`                | 3               |
| `critical`, `fatal`    | 4               |
| anything else          | 1               |

::: tip
The rule ID and stream name are URL-encoded and the tenant ID is validated before it goes into the token URL, so a bad config cannot redirect the request to another host or path.
:::

## Failure handling

A failed request puts the batch back at the front of the buffer and pauses threshold-triggered flushes for 1 s, doubling up to 30 s. HTTP 4xx responses other than 429 drop the batch with a warning. The buffer is capped by `maxBufferSize`, dropping the oldest first. Tokens are cached until a minute before they expire. `close()` flushes up to three times and reports anything undelivered.

## Related

- [Transports overview](/guide/transports/)
- [Graceful shutdown](/guide/graceful-shutdown)
- [CloudWatch transport](/guide/transports/cloudwatch) and [GCP transport](/guide/transports/gcp)
