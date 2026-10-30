---
title: AWS CloudWatch Transport
description: Send logixia logs to AWS CloudWatch Logs with batched PutLogEvents calls, no AWS SDK, SigV4 signing, a credential chain and optional EMF metrics.
order: 5
---

# AWS CloudWatch Transport

`CloudWatchTransport` batches log events and sends them to a CloudWatch Logs stream with `PutLogEvents`. It signs requests itself with AWS Signature Version 4, so you do not need the AWS SDK. It can also emit [Embedded Metric Format](https://docs.aws.amazon.com/AmazonCloudWatch/latest/monitoring/CloudWatch_Embedded_Metric_Format.html) records so numeric fields become CloudWatch Metrics.

## Quick start

Import it from `logixia/cloudwatch` and put an instance in `transports.custom`.

```ts
import { createLogger } from 'logixia';
import { CloudWatchTransport } from 'logixia/cloudwatch';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [
      new CloudWatchTransport({
        region: 'us-east-1',
        logGroupName: '/app/api',
        logStreamName: 'api-server-1',
        level: 'warn',
      }),
    ],
  },
});

await logger.warn('Slow query', { durationMs: 1200 });
await logger.close();
```

The log group and stream are created on first use, and an existing one is fine.

## Options

| Option             | Type       | Default                                                     | Description                                                            |
| ------------------ | ---------- | ----------------------------------------------------------- | ---------------------------------------------------------------------- |
| `logGroupName`     | `string`   | required                                                    | Log group name.                                                        |
| `region`           | `string`   | `AWS_REGION`, then `AWS_DEFAULT_REGION`, then `'us-east-1'` | AWS region.                                                            |
| `logStreamName`    | `string`   | `${HOSTNAME ?? 'node'}-${process.pid}`                      | Log stream name.                                                       |
| `endpoint`         | `string`   | `https://logs.<region>.amazonaws.com`                       | Override the endpoint, for example for LocalStack or a VPC endpoint.   |
| `accessKeyId`      | `string`   | credential chain                                            | AWS access key ID.                                                     |
| `secretAccessKey`  | `string`   | credential chain                                            | AWS secret access key. Used with `accessKeyId`.                        |
| `sessionToken`     | `string`   | none                                                        | Session token for temporary credentials.                               |
| `batchSize`        | `number`   | `100`                                                       | Events per request. Values above 10,000 are capped at 10,000.          |
| `flushIntervalMs`  | `number`   | `5000`                                                      | Send whatever is buffered after this many ms.                          |
| `emf`              | `boolean`  | `false`                                                     | Write EMF records instead of plain JSON.                               |
| `emfNamespace`     | `string`   | `'Logixia'`                                                 | CloudWatch Metrics namespace for EMF.                                  |
| `emfMetrics`       | `string[]` | unset                                                       | Payload fields to publish as metrics. Unset means every numeric field. |
| `requestTimeoutMs` | `number`   | `10000`                                                     | Abort a request that has not finished after this many ms.              |
| `maxBufferSize`    | `number`   | `10000`                                                     | Most buffered events; the oldest are dropped past this.                |
| `level`            | `string`   | unset                                                       | Minimum level to forward.                                              |

## Credentials

Credentials are looked up in this order, with no SDK:

1. `accessKeyId`, `secretAccessKey` and `sessionToken` in the config.
2. `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` and `AWS_SESSION_TOKEN`.
3. The shared credentials file (`~/.aws/credentials`, or `AWS_SHARED_CREDENTIALS_FILE`), using the `AWS_PROFILE` profile or `default`.
4. ECS container credentials (`AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` or `AWS_CONTAINER_CREDENTIALS_FULL_URI`, with `AWS_CONTAINER_AUTHORIZATION_TOKEN` or `AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE`).
5. EC2 instance metadata (IMDSv2). Set `AWS_EC2_METADATA_DISABLED=true` to skip it.

::: warning
SSO, assume-role profiles, `credential_process` and web identity (such as EKS IRSA) are not supported.
:::

The IAM identity needs `logs:CreateLogGroup`, `logs:CreateLogStream` and `logs:PutLogEvents`. If the group and stream already exist, `logs:PutLogEvents` is enough, and a failed `CreateLogGroup` is tolerated.

## What is sent

Without EMF, each CloudWatch event message is the whole entry serialized as JSON (`timestamp`, `level`, `message`, `data`, `context`, `traceId` and so on). Events in a request are sorted by timestamp, as CloudWatch requires.

## EMF metrics

With `emf: true`, each message becomes a flat JSON object with `level`, `message`, your payload keys and an `_aws` block. Numeric payload fields are published as metrics in `emfNamespace`, with a single `level` dimension and unit `None`. At most 100 metrics are listed per entry.

```ts
import { createLogger } from 'logixia';
import { CloudWatchTransport } from 'logixia/cloudwatch';

const logger = createLogger({
  appName: 'api',
  transports: {
    custom: [
      new CloudWatchTransport({
        logGroupName: '/app/api',
        emf: true,
        emfNamespace: 'MyApp',
        emfMetrics: ['duration'],
      }),
    ],
  },
});

await logger.info('Request completed', { duration: 142, statusCode: 200 });
```

Here only `duration` becomes a metric, because `emfMetrics` lists it. `statusCode` stays a plain log field.

## Failure handling

The transport buffers events and sends them from a single in-flight request at a time.

- A failed batch goes back to the front of the buffer in its original order. After a failure, threshold-triggered flushes pause for 1 s, doubling up to 30 s; the interval timer keeps trying.
- HTTP 4xx responses other than 429 mean the request will never be accepted, so the batch is dropped with a warning. Exceptions to that rule: `ThrottlingException`, `ThrottledException`, `LimitExceededException`, `ServiceUnavailableException`, `ExpiredTokenException` and `ResourceNotFoundException` are retried.
- `ResourceNotFoundException` makes the transport create the group and stream again. `ExpiredTokenException` refreshes credentials. `DataAlreadyAcceptedException` counts as success.
- The buffer is capped by `maxBufferSize`. The oldest events are dropped first, with a warning.
- With no credentials, events stay buffered (subject to the cap) and a warning is logged.
- `close()` waits for the request in flight, then tries up to three more flushes and reports anything still undelivered.

## Related

- [Transports overview](/guide/transports/)
- [Graceful shutdown](/guide/graceful-shutdown)
- [GCP transport](/guide/transports/gcp) and [Azure transport](/guide/transports/azure)
