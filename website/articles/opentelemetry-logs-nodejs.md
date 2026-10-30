---
title: 'OpenTelemetry Logs in Node.js: Correlate and Export over OTLP'
description: 'Correlate Node.js logs with OpenTelemetry traces and export them over OTLP to a Collector, Grafana Loki, Axiom or Better Stack with logixia.'
date: 2026-10-27
tags: [opentelemetry, otlp, tracing, observability, nodejs]
---

# OpenTelemetry Logs in Node.js: Correlate and Export over OTLP

**TL;DR:** OpenTelemetry logs in Node.js come down to two jobs. First, put the active trace ID into every log record so a backend can jump from a log line to its trace. Second, ship those records to a backend over OTLP. With logixia you do the first with a few lines around `@opentelemetry/api` and the second with the dependency-free `OtlpLogTransport`. This article shows both, plus the Collector, Grafana Loki, Axiom and Better Stack setups, and the places where the data model does not line up as neatly as you might hope.

Traces tell you _where_ a request spent its time. Logs tell you _why_. They are only as useful together as your ability to move between them, and that depends on one thing: the log record carrying the same trace ID as the span.

## What are OpenTelemetry logs?

In the OpenTelemetry data model a log is a **LogRecord**: a timestamp, a severity (a number from 1 to 24 plus a text like `INFO`), a body, a set of attributes, and optionally a `TraceId` and `SpanId`. A **Resource** describes the thing that emitted it (`service.name`, `service.version`, `deployment.environment`). Records are sent in batches over **OTLP**, the OpenTelemetry protocol, usually to a Collector at `http://host:4318/v1/logs` (HTTP) or port `4317` (gRPC).

The `TraceId` and `SpanId` fields are what make correlation work: a backend that sees a log with trace `4bf92f35...` can link it to the trace with the same ID.

## How do I add a trace ID to Node.js logs?

Two ways a trace ID can reach a log line.

**Propagation.** If an upstream service calls yours with a W3C `traceparent` header, an OpenTelemetry HTTP instrumentation continues that trace, and logixia's own trace-ID middleware also reads `traceparent` and keeps its 32-hex trace ID. In that case the IDs already agree.

**Taking it from the active span.** When no `traceparent` arrives, the OpenTelemetry SDK starts a new root trace while logixia would generate its own UUID, so the two disagree. The robust fix is to ask OpenTelemetry for the active span and hand its IDs to logixia's context. `LogixiaContext.run` accepts a `traceId`, which also becomes the logger's top-level trace ID inside that scope:

```ts
import { trace } from '@opentelemetry/api';
import type { RequestHandler } from 'express';
import { LogixiaContext } from 'logixia';

export const otelTraceContext: RequestHandler = (_req, _res, next) => {
  const spanContext = trace.getActiveSpan()?.spanContext();
  if (!spanContext) return next();
  LogixiaContext.run({ traceId: spanContext.traceId, spanId: spanContext.spanId }, next);
};
```

Register it after your OpenTelemetry HTTP instrumentation has started the server span (that normally happens before any Express middleware runs) and before your routes. Everything logged downstream, including from `await`ed code and `Promise.all`, now carries the span's trace ID, because the context rides on `AsyncLocalStorage`. If you have not met that mechanism, [the Express article](/articles/express-request-logging-trace-id) explains it, and the [tracing guide](/guide/tracing) covers the options.

A verified result: inside a manually started span, a logged record came out with the span's 32-hex trace ID as its trace ID and the span ID as a field. Because `spanId` is a plain payload field, it shows up as an attribute named `spanId`, not as the native `SpanId` of the OTLP record (more on that below).

For the OpenTelemetry side, see the [OpenTelemetry guide](/guide/opentelemetry) for SDK setup.

## How do I export logs over OTLP with logixia?

`OtlpLogTransport` builds an OTLP/HTTP **JSON** payload by hand and POSTs it with `fetch`. It needs no `@opentelemetry/*` logs packages. Add it as a custom transport:

```ts
import { createLogger } from 'logixia';
import { OtlpLogTransport } from 'logixia/transports';

export const logger = createLogger({
  appName: 'orders-api',
  environment: 'production',
  transports: {
    console: { format: 'json', colorize: false },
    custom: [
      new OtlpLogTransport({
        url: 'http://localhost:4318/v1/logs',
        serviceName: 'orders-api',
        serviceVersion: '1.4.2',
        environment: 'production',
        resourceAttributes: { 'service.namespace': 'shop' },
      }),
    ],
  },
});

await logger.info('order loaded', { orderId: 'o1' });
```

What it sends, checked against a local receiver:

- `resource.attributes`: `service.name` (default `logixia`), plus `service.version`, `deployment.environment` and anything in `resourceAttributes`. The transport does **not** read `OTEL_*` environment variables, so set these explicitly.
- `body`: the log message as a string.
- `severityNumber` and `severityText`: `trace` is 1, `debug` and `verbose` are 5, `info` is 9, `warn` is 13, `error` is 17, `fatal` is 21. A custom level falls back to `INFO`.
- `traceId`: set on the record when the entry's trace ID is a 32-character hex string (dashed UUIDs are normalized to hex). Anything else is sent as a `trace_id` attribute rather than dropped.
- `attributes`: your structured fields, plus `context`, `app.name` and `deployment.environment`. Strings, booleans and numbers keep their type; objects and arrays are JSON-encoded into a string.

Defaults: batches of `100` entries, a flush every `5000` ms, a `10000` ms request timeout and a `10000`-entry buffer cap with the oldest dropped when full. A failed batch goes back to the front of the buffer and is retried with backoff, but a 4xx other than 429 is treated as permanent and the batch is dropped with a warning.

### Which backends can I send to?

Only the URL and auth headers change. The transport needs the **full** URL, because it does not append `/v1/logs` for you.

**Local OpenTelemetry Collector** (the best first step, and the safest default):

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

Run it with `docker run --rm -p 4318:4318 -v "$PWD/otel-collector.yaml:/etc/otelcol-contrib/config.yaml" otel/opentelemetry-collector-contrib`, point `url` at `http://localhost:4318/v1/logs`, and every record prints to the Collector's stdout. From there you add whichever exporter your vendor documents, and the Collector converts to protobuf for you.

**Grafana Loki 3.x** accepts OTLP natively:

```ts
import { OtlpLogTransport } from 'logixia/transports';

export const loki = new OtlpLogTransport({
  url: 'http://loki:3100/otlp/v1/logs',
  serviceName: 'orders-api',
});
```

Self-hosted multi-tenant Loki also expects the usual `X-Scope-OrgID` header. For **Grafana Cloud**, copy the endpoint and credentials from the OpenTelemetry tile of your stack; the logs URL is the gateway URL plus `/v1/logs`, authenticated with Basic auth:

```ts
import { OtlpLogTransport } from 'logixia/transports';

const basic = Buffer.from(
  `${process.env.GRAFANA_INSTANCE_ID}:${process.env.GRAFANA_TOKEN}`
).toString('base64');

export const grafanaCloud = new OtlpLogTransport({
  url: 'https://otlp-gateway-<REGION>.grafana.net/otlp/v1/logs',
  headers: { Authorization: `Basic ${basic}` },
  serviceName: 'orders-api',
});
```

**Axiom** takes `Authorization: Bearer <token with ingest permission>` and an `X-Axiom-Dataset` header, at `https://<your-axiom-domain>/v1/logs`. **Better Stack** takes `Authorization: Bearer <source token>` at `https://<ingesting-host>/v1/logs`; the host and token are shown on the source's page.

```ts
import { OtlpLogTransport } from 'logixia/transports';

export const axiom = new OtlpLogTransport({
  url: `https://${process.env.AXIOM_DOMAIN}/v1/logs`,
  headers: {
    Authorization: `Bearer ${process.env.AXIOM_TOKEN}`,
    'X-Axiom-Dataset': process.env.AXIOM_DATASET!,
  },
  serviceName: 'orders-api',
});

export const betterStack = new OtlpLogTransport({
  url: `https://${process.env.BETTERSTACK_INGESTING_HOST}/v1/logs`,
  headers: { Authorization: `Bearer ${process.env.BETTERSTACK_SOURCE_TOKEN}` },
  serviceName: 'orders-api',
});
```

One honest caveat: vendor documentation for these services generally shows protobuf SDKs and Collector setups and does not explicitly promise that their logs endpoint accepts OTLP/HTTP **JSON**. If a backend rejects the body, send to a Collector and let it forward in protobuf. Treat host names in vendor docs as placeholders and copy the real values from your account. Header values are treated as secrets: logixia scrubs them from error messages, but keep them in environment variables anyway. See the [OTLP transport guide](/guide/transports/otlp) for the option reference.

## What gets lost in the mapping?

Correlation works at the **trace** level. Be aware of three details:

1. **`spanId` is an attribute.** The transport fills the native `TraceId` field but not the native `SpanId`. A backend that joins logs to individual spans by `SpanId` will not link them; one that joins by trace ID will. If per-span linking matters to you, check how your backend reads attributes.
2. **No `traceFlags`.** The sampled flag is not sent, so a log for an unsampled trace still carries a trace ID that points at nothing. That is normal OpenTelemetry behavior, but surprising the first time.
3. **Environment appears twice.** `deployment.environment` is set on the resource from the transport's `environment` option and again as a record attribute from the _logger's_ `environment` option, which defaults to `development`. Set both to the same value, as in the examples above, or you will see a mismatch in your backend.

## Pitfalls

- **Flush on shutdown.** Records are buffered for up to five seconds. Call `await logger.close()` in your SIGTERM handler (or enable `gracefulShutdown`) so the last batch leaves the process. See [shipping logs to Datadog and CloudWatch](/articles/ship-node-logs-to-datadog-and-cloudwatch) for the multi-destination version of this.
- **Don't export debug logs by accident.** Set `level: 'info'` on the transport to keep verbose output local.
- **Redact first.** Everything in the payload leaves the process. Configure [redaction](/articles/redact-sensitive-data-in-nodejs-logs) before you add a remote transport.
- **Test against the Collector's `debug` exporter** before pointing at a paid backend, so you can see the exact records.

## Key takeaways

- Correlation needs the same trace ID on the log and the span; take it from `trace.getActiveSpan()` when no `traceparent` arrives.
- `OtlpLogTransport` exports OTLP/HTTP JSON with no OpenTelemetry logs SDK. Give it the full `/v1/logs` URL.
- Trace-level linking works; the span ID travels as an attribute, not the native field.
- When in doubt about a vendor, go through a Collector.

## FAQ

**How do I send Node.js logs to an OpenTelemetry Collector?** Run a Collector with the OTLP HTTP receiver on port 4318, add `new OtlpLogTransport({ url: 'http://localhost:4318/v1/logs', serviceName })` to `transports.custom`, and log as normal.

**Do I need the OpenTelemetry SDK to use `OtlpLogTransport`?** No. It builds the payload itself and uses `fetch`. You only need `@opentelemetry/api` if you want to read the active span for correlation.

**Why don't my logs link to traces in Grafana or another backend?** Check that the log's trace ID equals the span's trace ID (32 hex characters). If logixia generated its own UUID because no `traceparent` arrived, wrap the request in `LogixiaContext.run` with the span's IDs as shown above.

**Does logixia support gRPC OTLP?** The transport speaks OTLP over HTTP with a JSON body. For gRPC backends, use a Collector as the bridge.
