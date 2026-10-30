---
title: Analytics Transports
description: Send logixia entries as events to Mixpanel, Segment or Google Analytics 4, with batching, reserved key handling, a bounded buffer and per-provider options.
order: 10
---

# Analytics Transports

The Mixpanel, Segment and Google Analytics transports turn log entries into product-analytics events. They share one batching base with the [Datadog transport](/guide/transports/datadog), so most behavior below applies to all of them.

Configure them under `transports.analytics`. Each key takes one config or an array.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'web',
  transports: {
    analytics: {
      mixpanel: { apiKey: '', token: process.env.MIXPANEL_TOKEN! },
      segment: { apiKey: '', writeKey: process.env.SEGMENT_WRITE_KEY! },
      googleAnalytics: {
        apiKey: '',
        measurementId: process.env.GA_MEASUREMENT_ID!,
        apiSecret: process.env.GA_API_SECRET!,
      },
    },
  },
});
```

::: warning
The shared analytics config type requires an `apiKey` string on every provider, but Mixpanel, Segment and Google Analytics do not read it. They use `token`, `writeKey` and `apiSecret`. Pass an empty string for `apiKey` to satisfy the type. Only Datadog uses `apiKey`.
:::

## Shared behavior

| Option                | Type                      | Default          | Description                                                                                                               |
| --------------------- | ------------------------- | ---------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `batchSize`           | `number`                  | `50`             | Entries collected before a send. A value of 1 or less sends each entry straight away.                                     |
| `flushInterval`       | `number` (ms)             | `10000`          | Send whatever is buffered after this long.                                                                                |
| `maxBufferSize`       | `number`                  | `10000`          | Most entries held while the provider is unreachable. Past it the oldest are dropped and counted. Never below `batchSize`. |
| `customProperties`    | `Record<string, unknown>` | unset            | Extra properties merged into every event.                                                                                 |
| `level`               | `string`                  | unset            | Minimum level for this transport.                                                                                         |
| `filter`              | `(entry) => boolean`      | unset            | Return `false` to skip an entry on this transport.                                                                        |
| `endpoint`            | `string`                  | provider default | Used by Mixpanel only.                                                                                                    |
| `enableUserTracking`  | `boolean`                 | `true`           | Gates Mixpanel's `identifyUser` and `setUserProperties`.                                                                  |
| `enableEventTracking` | `boolean`                 | `true`           | Gates Mixpanel's `trackCustomEvent`.                                                                                      |

What every analytics transport does:

- **Skips `debug` and `trace` entries.** They are never sent.
- **Validates its config on the first write.** A missing token or key makes every write fail with the same error instead of crashing at startup.
- **Re-buffers failures.** A failed batch goes back to the front of the buffer and the flush stops until the next timer tick or threshold. Datadog resends only the part of a batch that was not delivered.
- **Keeps your fields from overwriting core fields.** A payload key that clashes with a core field or a provider-reserved name is stored with a `data_` prefix.
- **Closes cleanly.** `close()` tries up to three flushes, then reports what could not be sent.

## Mixpanel

Events are named `log_<level>` (for example `log_error`) and posted to `https://api.mixpanel.com/track`.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'web',
  transports: {
    analytics: {
      mixpanel: {
        apiKey: '',
        token: process.env.MIXPANEL_TOKEN!,
        distinct_id: 'service-account',
        enableSuperProperties: true,
        superProperties: { platform: 'web' },
      },
    },
  },
});
```

| Option                  | Type                      | Default                    | Description                                          |
| ----------------------- | ------------------------- | -------------------------- | ---------------------------------------------------- |
| `token`                 | `string`                  | required                   | Mixpanel project token.                              |
| `distinct_id`           | `string`                  | `'anonymous'`              | `distinct_id` on every event.                        |
| `enableSuperProperties` | `boolean`                 | off                        | Merge `superProperties` into every event.            |
| `superProperties`       | `Record<string, unknown>` | unset                      | Properties added when `enableSuperProperties` is on. |
| `endpoint`              | `string`                  | `https://api.mixpanel.com` | API base URL, for example an EU or proxy endpoint.   |

Each event gets `time` (milliseconds), a `$insert_id` built from the timestamp, message and trace ID so retries do not create duplicates, plus the entry fields and your payload. `token`, `distinct_id`, `time` and `$insert_id` are reserved. Mixpanel answers `1` on success; any other reply is treated as an error.

Helpers on the class: `identifyUser({ id, properties })`, `setUserProperties(userId, properties)` and `trackCustomEvent(name, properties)`.

## Segment

Events are named `Log <Level>` (for example `Log Error`) and sent to `/v1/batch`, or `/v1/track` when batching is off. The write key is sent with Basic auth.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'web',
  transports: {
    analytics: {
      segment: {
        apiKey: '',
        writeKey: process.env.SEGMENT_WRITE_KEY!,
        userIdField: 'userId',
        maxBatchSize: 100,
      },
    },
  },
});

await logger.info('Plan upgraded', { userId: 'u_42', plan: 'pro' });
```

| Option           | Type          | Default                  | Description                                                                        |
| ---------------- | ------------- | ------------------------ | ---------------------------------------------------------------------------------- |
| `writeKey`       | `string`      | required                 | Segment write key.                                                                 |
| `dataPlaneUrl`   | `string`      | `https://api.segment.io` | API base URL, for example a regional or proxy endpoint.                            |
| `userIdField`    | `string`      | `'userId'`               | Payload field read as the Segment `userId`. Only string values are used.           |
| `enableBatching` | `boolean`     | `true`                   | Send many events in one `/v1/batch` call. If `false`, entries are sent one by one. |
| `maxBatchSize`   | `number`      | `100`                    | Events per `/v1/batch` request.                                                    |
| `flushInterval`  | `number` (ms) | `10000`                  | Same as the shared option.                                                         |
| `flushAt`        | `number`      | none                     | Declared in the type but not used. Use `batchSize` to control when a send starts.  |

Each event carries a random `anonymousId`, the entry fields as `properties`, and a `context.library` of `logixia`. When the entry has a trace ID, it is also put in `context.trace.trace_id`. `logger` is a reserved property name.

Helpers on the class: `identify`, `page`, `screen`, `group`, `alias`, `trackCustomEvent`, `trackPurchase` and `trackProductViewed`.

## Google Analytics 4

Entries are sent as `log_event` events through the GA4 Measurement Protocol, up to 25 events per request.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'web',
  transports: {
    analytics: {
      googleAnalytics: {
        apiKey: '',
        measurementId: process.env.GA_MEASUREMENT_ID!,
        apiSecret: process.env.GA_API_SECRET!,
        clientId: 'server-1',
      },
    },
  },
});
```

| Option                      | Type      | Default            | Description                                                         |
| --------------------------- | --------- | ------------------ | ------------------------------------------------------------------- |
| `measurementId`             | `string`  | required           | GA4 measurement ID, such as `G-XXXXXXX`.                            |
| `apiSecret`                 | `string`  | required           | Measurement Protocol API secret.                                    |
| `clientId`                  | `string`  | random per request | GA4 `client_id`.                                                    |
| `enableEnhancedMeasurement` | `boolean` | off                | Enables the `trackFileDownload` and `trackVideoEngagement` helpers. |
| `enableEcommerce`           | `boolean` | none               | Declared in the type but not used.                                  |

Event parameters include `event_category` (from the level), `event_label` and `log_message` (the message), `log_level`, `timestamp`, `trace_id`, `app_name`, `environment` and three custom dimensions (level, context, environment). Your payload is flattened into `parent_child` keys, and every value is converted to a string and cut to 100 characters to fit GA4 limits. Those parameter names are reserved.

Helpers on the class include `trackPageView`, `trackCustomEvent`, `trackConversion`, `trackError` and `setUserProperties`.

## Related

- [Datadog transport](/guide/transports/datadog)
- [Redaction](/guide/redaction) so personal data never reaches an analytics provider
- [Transports overview](/guide/transports/)
