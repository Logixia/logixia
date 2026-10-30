---
title: Slack and Discord Transports
description: Post logixia error alerts to Slack incoming webhooks or Discord webhooks with batching, mention-safe escaping, 429 retry handling and custom formatters.
order: 11
---

# Slack and Discord Transports

`SlackTransport` and `DiscordTransport` send log entries to a chat channel through an incoming webhook. By default they send only `error` and `fatal` entries, which makes them a good fit for alerts.

Both are exported from `logixia` and `logixia/transports`. Add them through `transports.custom`.

## Quick start

```ts
import { createLogger, DiscordTransport, SlackTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  transports: {
    custom: [
      new SlackTransport({ webhookUrl: process.env.SLACK_WEBHOOK_URL!, level: 'error' }),
      new DiscordTransport({ webhookUrl: process.env.DISCORD_WEBHOOK_URL!, level: 'warn' }),
    ],
  },
});

await logger.error('Database unreachable', { host: 'db-1' });
await logger.close();
```

## Options

Both transports take the same options, plus a few provider-specific ones.

| Option             | Type                 | Default   | Description                                                                                                                                                   |
| ------------------ | -------------------- | --------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `webhookUrl`       | `string`             | required  | The webhook URL. It is a secret.                                                                                                                              |
| `level`            | `string`             | `'error'` | Minimum level to send. One of `fatal`, `error`, `warn`, `warning`, `info`, `debug`, `verbose`, `trace`. An unknown name throws when the transport is created. |
| `minIntervalMs`    | `number`             | `1000`    | Entries within this window are batched into one message.                                                                                                      |
| `maxRetries`       | `number`             | `1`       | Retries after an HTTP 429. The wait comes from the response (`Retry-After`, or `retry_after` for Discord) and is capped at 30 s.                              |
| `maxBufferSize`    | `number`             | `1000`    | Most queued entries; the oldest are dropped past this.                                                                                                        |
| `requestTimeoutMs` | `number`             | `10000`   | Abort a request that has not finished after this many ms.                                                                                                     |
| `allowCustomUrl`   | `boolean`            | off       | Accept an `https` webhook URL on any host, such as a proxy or a compatible service.                                                                           |
| `formatter`        | function             | built-in  | Build the message yourself. See below.                                                                                                                        |
| `filter`           | `(entry) => boolean` | unset     | Return `false` to skip an entry.                                                                                                                              |
| `username`         | `string`             | unset     | Override the display name. Cut to 80 characters.                                                                                                              |

Slack adds `iconEmoji`. Discord adds `avatarUrl`, which must be an `https` URL.

## Webhook URL rules

The URL is checked when the transport is created, and the error messages never include it.

- It must use `https`, and must not contain a username or password.
- Slack accepts `hooks.slack.com` and `hooks.slack-gov.com` with a path starting `/services/` or `/triggers/`. Discord accepts `discord.com` and `discordapp.com` webhook URLs.
- Anything else throws, unless you set `allowCustomUrl: true`.

The transports hide the URL from `JSON.stringify` and `util.inspect`. Read it from the environment, not from source.

## How messages are built

### Slack

Each entry becomes a Block Kit message: a header with `[LEVEL] message`, a context line with `app`, `env`, `context`, `trace` and `time` when present, and the payload as a code block (cut to 2,500 characters). Entries inside the `minIntervalMs` window are merged into one message of at most 10 entries, and the overflow is reported as "and N more entries not shown". A message holds at most 50 blocks.

All logged text is escaped for Slack (`&`, `<`, `>`), which also disarms `<!channel>`, `<!here>` and `<@U123>` mentions that came from logged data.

### Discord

Each entry becomes an embed with a colored title, fields for `appName`, `environment`, `context` and `traceId`, a timestamp, and the payload as a JSON code block. A request carries at most 10 embeds, and the overflow is counted in the message `content`. Discord's size limits (title 256, description 4,096, 6,000 characters across an embed set) are enforced for you. Every request sets `allowed_mentions: { parse: [] }`, so logged data can never ping `@everyone`, roles or users, and logged text has its markdown escaped.

## Custom formatters

A `formatter` replaces the default message for each entry. You become responsible for escaping the content. If the formatter throws, logixia warns and falls back to the default message.

```ts
import { createLogger, DiscordTransport, SlackTransport } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: {
    custom: [
      new SlackTransport({
        webhookUrl: process.env.SLACK_WEBHOOK_URL!,
        formatter: (entry) => ({ text: `:fire: ${entry.level}: ${entry.message}` }),
      }),
      new DiscordTransport({
        webhookUrl: process.env.DISCORD_WEBHOOK_URL!,
        formatter: (entry) => ({
          title: entry.message.slice(0, 200),
          color: 0xed4245,
          fields: [{ name: 'context', value: entry.context ?? 'none', inline: true }],
        }),
      }),
    ],
  },
});
```

For Slack, the results of one window are merged: texts are joined and blocks are concatenated. For Discord, the embed is clamped to the limits.

## Failure handling

- An HTTP 429 waits for the time the server gives (up to 30 s) and retries up to `maxRetries` times.
- An entry that cannot be rendered is dropped on its own. A batch that cannot be serialized, or a runtime without a global `fetch`, is dropped rather than retried.
- The queue is bounded by `maxBufferSize`, dropping the oldest entries first.
- `close()` flushes what is queued and cancels any pending 429 wait. Once closing, each request is limited to 3 seconds (or `requestTimeoutMs` if that is lower).

::: tip
Keep chat transports at `error` or `warn`. Even with batching, an `info` stream will fill a channel quickly.
:::

## Related

- [Transports overview](/guide/transports/)
- [Redaction](/guide/redaction) to keep secrets out of alerts
- [Sampling](/guide/sampling) to rate-limit noisy errors
