---
title: 'Ship Node.js Logs to Datadog and CloudWatch with logixia'
description: 'Send Node.js logs to Datadog and AWS CloudWatch together: batching, retries, buffer limits, site and credential setup, and when an agent is better.'
date: 2026-10-29
tags: [datadog, cloudwatch, aws, log-shipping, nodejs]
---

# Ship Node.js Logs to Datadog and CloudWatch with logixia

**TL;DR:** You can ship Node.js logs to Datadog and AWS CloudWatch directly from your logger, in parallel with stdout, using logixia's `DataDogTransport` and `CloudWatchTransport`. Neither needs a vendor SDK. Batching, bounded buffers and a flush on shutdown are built in. The catches are credentials (use IAM roles, not keys in code), the right Datadog `site`, and remembering that an agent reading stdout is often the better design. This article covers both approaches and how to configure the in-process one safely.

There are two ways to get logs out of a Node process, and the choice matters more than the vendor.

## Should I ship logs from the app or use an agent?

**Option 1, write to stdout and let the platform ship it.** The app writes JSON lines to stdout. A collector (the Datadog Agent, the CloudWatch agent, Fluent Bit, ECS's `awslogs` driver, Lambda's built-in capture) reads them and forwards them. Your app has no network dependency on the log backend, no buffering logic, and no credentials for it. This is the default recommendation wherever you can run a collector.

**Option 2, ship from inside the process.** The logger sends batches over HTTPS itself. Choose this when you cannot run an agent: small VMs, some serverless and edge runtimes, or when you want one config to feed several destinations. The cost is that the app now owns delivery: batching, retries, memory use under backpressure, and credentials.

Do not do both to the same destination. If your agent already collects stdout, also sending in-process to the same backend gives you duplicate logs and a double bill.

The rest of this article covers option 2, because that is where the configuration lives.

## What does a good in-process shipper need?

1. **Batching.** One HTTP request per log line is slow and expensive. Send groups of entries, flushed when full or after a time limit.
2. **Bounded memory.** If the backend is down, the buffer must not grow without limit. Dropping the oldest entries is the usual policy, and it should be counted and reported.
3. **Retries with backoff.** Retry transient failures (network errors, 429, 5xx); do not retry requests the server will never accept (most 4xx).
4. **Flush on shutdown.** The last seconds before a deploy or crash are the ones you want most.
5. **No secrets in errors or output.** An exception from the HTTP layer must not contain your API key.
6. **Level routing.** Verbose logs stay local; only what you pay to store leaves the process.

## How do I send logs to Datadog?

Add the Datadog transport under `transports.analytics.datadog`. Set `site` to match your Datadog account's region; the default is `datadoghq.com`.

```ts
import { createLogger } from 'logixia';

export const logger = createLogger({
  appName: 'checkout-api',
  environment: 'production',
  transports: {
    console: { format: 'json', colorize: false },
    analytics: {
      datadog: {
        apiKey: process.env.DD_API_KEY!,
        site: 'datadoghq.eu',
        service: 'checkout-api',
        env: 'production',
        version: process.env.APP_VERSION ?? 'dev',
        level: 'info',
        compress: true,
      },
    },
  },
  gracefulShutdown: true,
});

await logger.info('order placed', { orderId: 'o_1', amountCents: 4900 });
```

Supported `site` values are `datadoghq.com`, `datadoghq.eu`, `us3.datadoghq.com`, `us5.datadoghq.com`, `ap1.datadoghq.com` and `ddog-gov.com`. Logs go to `https://http-intake.logs.<site>/api/v2/logs` with the key in the `DD-API-KEY` header, never in the URL. What you get:

- Each log carries `ddsource: nodejs`, `service`, `status` (mapped from the logixia level), a `hostname`, and `ddtags` built from `env`, `service` and `version`. Your structured fields become attributes.
- Requests are split into chunks of at most 1,000 entries and about 5 MB. A single log over 1 MB keeps its identifying fields but loses its attributes and most of its message, and is marked `truncated`.
- `compress: true` gzips request bodies.
- The trace ID is converted to the decimal 64-bit form Datadog uses and sent as `dd.trace_id`; a `spanId` field in your payload becomes `dd.span_id`. Whether that links to your traces depends on your tracer producing the same ID, so verify it in your account.
- Defaults: batches of `50`, a flush every `10000` ms, and a `10000`-entry buffer cap. Set `batchSize`, `flushInterval` and `maxBufferSize` to change them.
- **`debug` and `trace` entries are skipped** by the analytics transports. If you expect debug logs in Datadog, they will not arrive.
- Optional `enableMetrics: true` also sends a per-level count metric. It is off by default, and the metric names still start with the legacy prefix `logitron.logs.`.

The [Datadog transport guide](/guide/transports/datadog) lists every option.

## How do I send logs to CloudWatch?

`CloudWatchTransport` calls the CloudWatch Logs API (`PutLogEvents`) over HTTPS and signs requests with AWS Signature V4 itself, so you do not install the AWS SDK. Pass it as a custom transport:

```ts
import { createLogger } from 'logixia';
import { CloudWatchTransport } from 'logixia/transports';

export const logger = createLogger({
  appName: 'checkout-api',
  environment: 'production',
  transports: {
    console: { format: 'json', colorize: false },
    custom: [
      new CloudWatchTransport({
        region: 'eu-west-1',
        logGroupName: '/shop/checkout-api',
        logStreamName: `api-${process.env.HOSTNAME ?? 'local'}`,
        level: 'info',
        batchSize: 100,
        flushIntervalMs: 5000,
      }),
    ],
  },
  gracefulShutdown: true,
});

await logger.warn('inventory low', { sku: 'A-100', remaining: 3 });
```

Details worth knowing:

- The log **group and stream are created on first use** if they do not exist, so the role needs `logs:CreateLogGroup`, `logs:CreateLogStream` and `logs:PutLogEvents`. If you pre-create them, you can drop the first two.
- The default stream name is `<hostname>-<pid>`, and the region falls back to `AWS_REGION`, then `AWS_DEFAULT_REGION`, then `us-east-1`. Set `region` explicitly.
- Each event's message is the JSON of the log entry, with your fields under a `data` key. Events are sorted by timestamp before sending, and a duplicate-delivery response is treated as success.
- `batchSize` defaults to `100` and is capped at CloudWatch's 10,000 events per call; the interval defaults to `5000` ms; the buffer is capped at `10000` events, oldest dropped first.
- Optional **EMF** (`emf: true`) writes entries in Embedded Metric Format so numeric fields become CloudWatch metrics under the `Logixia` namespace (change it with `emfNamespace`, restrict fields with `emfMetrics`).
- Retries use exponential backoff (1 s doubling to a 30 s cap). Throttling and expired-token errors are retried even though CloudWatch reports them as HTTP 400; other 4xx errors are treated as permanent and the batch is dropped with a warning.

See [CloudWatch in the guide](/guide/transports/cloudwatch) for the reference.

### How does the transport authenticate to AWS?

In order: explicit `accessKeyId` / `secretAccessKey` / `sessionToken` in config, then environment variables, then the shared credentials file (honoring `AWS_PROFILE` and `AWS_SHARED_CREDENTIALS_FILE`), then ECS container credentials, then EC2 instance metadata (IMDSv2). **SSO, assume-role profiles and `credential_process` are not supported**, and web-identity (for example IRSA on Kubernetes) is not in the list, so test your environment before relying on it. On Lambda, ECS and EC2 the role-based paths work without any keys in your config.

## How do I send to Datadog, CloudWatch and stdout at once?

Combine them in one `transports` object, with a level per destination so each one only receives what is worth paying for:

```ts
import { createLogger } from 'logixia';
import { CloudWatchTransport } from 'logixia/transports';

export const logger = createLogger({
  appName: 'checkout-api',
  environment: 'production',
  levelOptions: { level: 'debug' },
  transports: {
    console: { format: 'json', colorize: false, level: 'debug' },
    analytics: {
      datadog: {
        apiKey: process.env.DD_API_KEY!,
        site: 'datadoghq.com',
        service: 'checkout-api',
        env: 'production',
        level: 'info',
      },
    },
    custom: [
      new CloudWatchTransport({
        region: 'us-east-1',
        logGroupName: '/shop/checkout-api',
        level: 'warn',
      }),
    ],
  },
  gracefulShutdown: true,
});
```

Every transport receives every entry that passes its own level check, so one slow or failing destination does not stop the others: a failure in one is caught, reported and does not block the rest of the entry's delivery.

## Credentials hygiene

- **Environment or secret manager, never source.** `DD_API_KEY` comes from the environment, injected by your orchestrator.
- **Roles over keys on AWS.** Give the workload an IAM role with the three `logs:` actions scoped to the one log group. Static keys in config are the fallback, not the plan.
- **Separate keys per environment**, and rotate on staff changes or any suspected leak.
- **Keep secrets out of output.** logixia keeps transport credentials out of serialized output (`JSON.stringify`, `util.inspect`) and scrubs configured secret values from error text, so an accidental `logger.error(err)` after a failed upload will not print your key. Do not rely on it as the only safeguard; see [Security](/guide/security).
- **Redact the log content too.** Everything in the payload goes to a third party; see [redacting sensitive data](/articles/redact-sensitive-data-in-nodejs-logs).

## Pitfalls

- **Wrong Datadog `site`.** A key from the EU site will be rejected by the US intake. Confirm the site in your account URL.
- **Missing flush.** Without `gracefulShutdown: true` or an explicit `await logger.close()`, the last batch can be lost on exit.
- **Silent drops.** When a buffer fills, the oldest entries are dropped and a warning goes to stderr. Watch stderr, or use `logger.healthCheck()` in a readiness probe.
- **Duplicates.** Do not combine in-process shipping with an agent tailing stdout for the same backend.
- **Cost.** Shipping `info` for a chatty service is a real bill. Pair this with [sampling](/guide/sampling) and per-transport levels.
- **No console output.** Because `transports` lists only what you specify, add `console` explicitly (the examples do).

If you would rather standardize on one open format, [OTLP export](/articles/opentelemetry-logs-nodejs) covers that route, and the [transports overview](/guide/transports/) lists everything available.

## Key takeaways

- Prefer an agent reading stdout where you can run one; ship in-process where you cannot.
- `DataDogTransport` (via `analytics.datadog`) and `CloudWatchTransport` (via `custom`) batch, cap memory, retry and flush on shutdown.
- Set the Datadog `site` and AWS `region` explicitly; use roles, not static keys.
- Route by level so each destination gets only what it should.

## FAQ

**How do I send Node.js logs to Datadog without the Datadog Agent?** Use `transports.analytics.datadog` with your API key and `site`. The transport posts batched logs to Datadog's HTTP intake with the key in a header.

**How do I send Node.js logs to CloudWatch without the AWS SDK?** Add `new CloudWatchTransport({ region, logGroupName })` to `transports.custom`. It signs requests itself and uses the standard credential sources.

**Will I lose logs if my app crashes?** Buffered entries (up to a few seconds' worth) can be lost on a hard crash. Graceful shutdown flushes on SIGTERM/SIGINT; stdout plus an agent is the most robust option.

**Can I send to several destinations with different levels?** Yes. Each transport takes its own `level`, so you can keep `debug` on the console, `info` in Datadog and `warn` in CloudWatch.
