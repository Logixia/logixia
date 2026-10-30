---
title: 'Send Node.js Error Alerts to Slack and Discord from Logs'
description: 'Turn error logs into Slack and Discord alerts without alert storms, accidental @everyone pings or leaked webhook URLs. Working logixia examples.'
date: 2026-10-29
tags: [alerting, slack, discord, webhooks, nodejs]
---

# Send Node.js Error Alerts to Slack and Discord from Logs

**TL;DR:** You can send error alerts to Slack and Discord straight from your logger by adding a webhook transport that only fires at `error` level. The parts that matter are the ones people skip: batching so one bad deploy does not post 4,000 messages, escaping so logged data cannot ping `@everyone`, and treating the webhook URL as the credential it is. logixia ships `SlackTransport` and `DiscordTransport` that handle those three things by default.

Chat alerts are the lowest-friction way to learn that production is on fire. They are also easy to get wrong in ways that make people mute the channel, which is worse than having no alert at all. This article covers the design, then a working setup.

## Should you alert from logs at all?

Be honest about what a webhook alert is. It is a _notification_, not an incident-management system: there is no acknowledgement, no escalation and no on-call schedule. For anything that must wake someone up, route through a pager (PagerDuty, Opsgenie, Alertmanager) and use chat as the visible second channel.

Alerting from logs is a good fit for:

- Unhandled exceptions and `5xx` responses that you want a human to glance at.
- Rare, high-signal events (a payment webhook failed signature verification, a cron job missed its window).
- Small teams that have no metrics pipeline yet.

It is a poor fit for high-volume conditions ("error rate above 2%"). Those belong in a metrics system where you can set thresholds and windows.

## What makes a good log-based alert?

1. **Level filtering.** Only `error` and above should leave the process for chat. Everything else stays in your log store.
2. **Throttling and batching.** A failing dependency can produce thousands of identical errors per minute. Without a limit you will hit the chat provider's rate limit (and your own patience) within seconds.
3. **Context in the message.** An alert that says "Error: failed" is noise. Include the app, environment, trace ID and the structured fields so the on-call can search the full logs.
4. **Mention safety.** Logged data is attacker-influenced. If a user-supplied string reaches a Slack message, `<!channel>` or `@everyone` inside it can ping the whole workspace.
5. **Secret hygiene.** A webhook URL lets anyone post to your channel. It must never appear in logs, error messages or source control.

## How do I send logixia errors to Slack?

Create an [incoming webhook](https://api.slack.com/messaging/webhooks) for the channel, store the URL in an environment variable, and add a `SlackTransport`. The default minimum level is already `error`.

```ts
import { createLogger } from 'logixia';
import { SlackTransport } from 'logixia/transports';

const logger = createLogger({
  appName: 'checkout-api',
  environment: 'production',
  transports: {
    console: { format: 'json', colorize: false },
    custom: [
      new SlackTransport({
        webhookUrl: process.env.SLACK_WEBHOOK_URL!,
        username: 'checkout-api',
        iconEmoji: ':rotating_light:',
      }),
    ],
  },
});

await logger.error(new Error('payment provider timed out'), { orderId: 'ord_123' });
```

Two things to notice. First, the `console` transport is declared explicitly: when you pass a `transports` object, logixia only creates the destinations you list, so a config with just `custom` produces no console output. Second, `SlackTransport` validates the URL at construction: it must be `https` on `hooks.slack.com` (or `hooks.slack-gov.com`), otherwise it throws a `TypeError` that never includes the URL itself. If you front Slack with a proxy, pass `allowCustomUrl: true`.

The default message is a Block Kit message with the level and message as a header, a context line with `app`, `env`, `context`, `trace` and `time`, and the structured fields as a JSON code block. The trace ID is what lets you jump from the alert to the full request log; see [request tracing in NestJS](/articles/nestjs-logging-with-request-tracing) or [Express](/articles/express-request-logging-trace-id).

## How do I send logixia errors to Discord?

Create a webhook under **Channel settings, Integrations, Webhooks** and use `DiscordTransport`. It sends embeds, colored by level.

```ts
import { createLogger } from 'logixia';
import { DiscordTransport } from 'logixia/transports';

const logger = createLogger({
  appName: 'checkout-api',
  environment: 'production',
  transports: {
    console: { format: 'json', colorize: false },
    custom: [
      new DiscordTransport({
        webhookUrl: process.env.DISCORD_WEBHOOK_URL!,
        username: 'checkout-api',
        level: 'error',
      }),
    ],
  },
});

await logger.error('inventory sync failed', { sku: 'A-100', attempts: 3 });
```

The URL must be an `https` webhook on `discord.com` or `discordapp.com` unless you set `allowCustomUrl`. Both transports are also exported from the root `logixia` entry, and they work side by side.

## How does logixia stop alert storms?

Both transports share one throttled queue:

- **Windowed batching.** The first entry goes out immediately; entries that arrive within `minIntervalMs` (default `1000`) are combined into a single message.
- **Per-message cap.** A message carries at most 10 entries. Extras are not sent: the message ends with a "… and N more" line and an internal warning records the count.
- **Bounded memory.** The queue holds at most `maxBufferSize` entries (default `1000`); the oldest are dropped first.
- **Rate-limit handling.** On HTTP 429 the transport waits for `Retry-After` (capped at 30 seconds) and retries up to `maxRetries` times (default `1`).
- **Timeouts.** Requests abort after `requestTimeoutMs` (default `10000`).

This is **batching, not deduplication**: 500 identical errors in one window still count as 500 entries (you see ten and "490 more"). If you want to suppress repeats of the same error for a while, add a `filter`, which runs after the level check:

```ts
import { createLogger } from 'logixia';
import { SlackTransport } from 'logixia/transports';

const lastSeen = new Map<string, number>();
const QUIET_MS = 5 * 60_000;

const slack = new SlackTransport({
  webhookUrl: process.env.SLACK_WEBHOOK_URL!,
  filter: (entry) => {
    const now = Date.now();
    const last = lastSeen.get(entry.message) ?? 0;
    if (now - last < QUIET_MS) return false;
    lastSeen.set(entry.message, now);
    return true;
  },
});

export const logger = createLogger({
  appName: 'checkout-api',
  transports: { console: { format: 'json', colorize: false }, custom: [slack] },
});
```

Keep a plain `Map` like this bounded in real code (for example, delete entries older than `QUIET_MS` periodically), and key on something stable such as the message plus context rather than a message with an embedded ID.

## Can logged data ping @everyone?

Not with these transports, by design:

- **Slack:** all logged text is escaped for mrkdwn (`&`, `<`, `>`), which also disarms `<!channel>`, `<!here>` and `<@U123>` mentions that arrive through logged data.
- **Discord:** every request carries `allowed_mentions: { parse: [] }`, so no content can ping roles, users or `@everyone`, and markdown in logged text is escaped.

The exception is a custom `formatter`. If you supply one, the transport enforces size limits but escaping becomes your responsibility. Unless you need a different layout, use the default.

## How do I keep the webhook URL secret?

Treat it like a password: anyone holding it can post into your channel.

- Load it from the environment or a secret manager (`process.env.SLACK_WEBHOOK_URL`), never from source.
- Use a different webhook per environment, and only attach the transport in production, so staging noise does not reach the same channel.
- logixia never logs the URL and error messages name only the host. The transport also hides the URL from `JSON.stringify` and `util.inspect`, so accidentally logging the logger config does not leak it.
- If a URL leaks, revoke it in Slack or Discord and issue a new one; there is no other fix.

Also redact before you alert. The structured fields are posted to a third party, so apply [log redaction](/articles/redact-sensitive-data-in-nodejs-logs) to keep tokens and personal data out of chat history.

## Pitfalls

- **No flush on exit.** Alerts are queued. Call `await logger.close()` on shutdown, or enable `gracefulShutdown`, so the last error before a crash is delivered. `close()` makes a best-effort send with a short timeout, so a dead webhook cannot hang shutdown.
- **Alerting on `warn`.** Lowering `level` to `warn` is rarely worth it; chat channels full of warnings get muted.
- **Missing context.** If errors carry no `orderId`, `userId` or trace ID, the alert tells the reader nothing. Attach fields at the call site or with a [child logger](/articles/structured-logging-typescript).
- **Stack traces in chat.** When you log an `Error`, its stack becomes part of the structured fields the default message posts, file paths included. If that is more than you want in a shared channel, narrow it with a `filter`, or write a custom `formatter` (remembering that escaping then becomes your job).
- **Relying on chat for paging.** See above: add a real pager for anything urgent.

For other destinations see the [Slack and Discord transport guide](/guide/transports/slack-discord) and the [transports overview](/guide/transports/).

## Key takeaways

- Filter by level, batch by window, and escape everything: the shipped transports do all three.
- Declare `console` yourself when you add other transports.
- Webhook URLs are credentials. Keep them in the environment, one per environment.
- Throttling is not deduplication; add a `filter` if you need it.

## FAQ

**How do I send Node.js errors to a Slack channel?** Create an incoming webhook, set `SLACK_WEBHOOK_URL`, and add `new SlackTransport({ webhookUrl })` to `transports.custom`. It sends `error`-level entries by default.

**Will a burst of errors spam my Discord channel?** No. Entries within one second (`minIntervalMs`) are merged into one request, a request carries at most 10 embeds, and 429 responses are honored with `Retry-After`.

**Can I alert on `warn` as well as `error`?** Yes, set `level: 'warn'` on the transport. Expect more noise and consider a `filter` for specific contexts.

**Is it safe to log user input if it goes to Slack?** Mentions in logged text are neutralized, but the data itself still lands in a third-party tool. Redact sensitive fields first.
