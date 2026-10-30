---
title: OpenTelemetry integration
description: Correlate logixia logs with OpenTelemetry traces using initOtelBridge, read the active span context, and export logs over OTLP with OtlpLogTransport.
order: 12
---

# OpenTelemetry integration

logixia works with OpenTelemetry in two ways: it can add the active span's IDs to every entry, and it can export logs to an OTLP endpoint.

## Trace-log correlation

`@opentelemetry/api` is an optional dependency that logixia loads on demand. If it is installed and your OpenTelemetry SDK is running, call `initOtelBridge()` once at startup, after the SDK is initialised:

```ts
import { createLogger, initOtelBridge } from 'logixia';

initOtelBridge();

const logger = createLogger({ appName: 'api' });
await logger.info('inside a span'); // payload gets traceId, spanId and traceFlags
```

From then on, every log call looks up the active span and merges `traceId` (32 hex characters), `spanId` (16 hex characters) and `traceFlags` into the payload. Without an active valid span nothing is added. If `@opentelemetry/api` is not installed, the helpers silently return nothing.

These fields are in the payload. The entry's separate top-level `traceId` still comes from logixia's own [trace context](/guide/tracing).

### Options

`initOtelBridge(options)` accepts:

| Option            | Default        | Description                         |
| ----------------- | -------------- | ----------------------------------- |
| `traceIdField`    | `'traceId'`    | Payload key for the trace ID.       |
| `spanIdField`     | `'spanId'`     | Payload key for the span ID.        |
| `traceFlagsField` | `'traceFlags'` | Payload key for the flags.          |
| `sampledOnly`     | `false`        | Add the IDs only for sampled spans. |

`disableOtelBridge()` turns the bridge off, which is useful in tests.

### Manual use

```ts
import { createLogger, getActiveOtelContext, getOtelMetaFields } from 'logixia';

const logger = createLogger({ appName: 'api' });

const ctx = getActiveOtelContext();
if (ctx) {
  console.log(ctx.traceId, ctx.spanId, ctx.traceFlags, ctx.isSampled);
}

await logger.info('payment processed', { ...getOtelMetaFields(), orderId: 'ord_123' });
```

`getActiveOtelContext()` returns an `OtelSpanContext` or `undefined`. `getOtelMetaFields()` returns the fields as a plain object (empty when there is no span). These functions are also available from `logixia/browser`.

## Exporting logs over OTLP

`OtlpLogTransport` posts logs as OTLP/HTTP with a JSON body, so any OTLP-compatible collector or backend can receive them. It needs no OpenTelemetry SDK. Add it through `transports.custom`:

```ts
import { createLogger } from 'logixia';
import { OtlpLogTransport } from 'logixia/transports';

const logger = createLogger({
  appName: 'api',
  transports: {
    custom: [
      new OtlpLogTransport({
        url: 'http://localhost:4318/v1/logs',
        serviceName: 'api',
      }),
    ],
  },
});

await logger.info('exported');
await logger.close();
```

Options, severity mapping and backend recipes (a local Collector, Grafana Cloud Loki, Axiom, Better Stack) are in [OTLP transport](/guide/transports/otlp).
