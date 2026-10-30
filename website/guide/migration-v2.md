---
title: Migrating to 2.0
description: 'Upgrade logixia from 1.x to 2.0: NestJS exports moved to logixia/nest, plus behaviour changes from 1.13.3 to 2.0.4 in redaction, transports and tracing.'
order: 23
---

# Migrating to 2.0

Version 2.0 has one breaking change: the NestJS exports moved to their own entry point. The releases around it (1.13.x and 2.0.x) also tightened several defaults, which you may notice in output. This page covers both.

## Which versions exist

Some tags were created but never published to npm. Upgrade to a published version:

| Version             | On npm | Notes                                                                 |
| ------------------- | ------ | --------------------------------------------------------------------- |
| 1.13.0              | yes    | Adds `trustIncoming` to the correlation middleware.                   |
| 1.13.1, 1.13.2      | no     | Superseded; their changes ship in 1.13.3.                             |
| 1.13.3              | yes    | Contains the 1.13.1 and 1.13.2 changes plus a publish fix.            |
| 2.0.0               | yes    | The breaking change below, Slack and Discord transports, Datadog fix. |
| 2.0.1, 2.0.2, 2.0.3 | no     | Superseded; their changes ship in 2.0.4.                              |
| 2.0.4               | yes    | Contains everything above.                                            |

If you are on 1.x, go straight to the latest 2.x.

## Breaking change: NestJS imports

`LogixiaLoggerModule`, `LogixiaLoggerService`, `LogixiaExceptionFilter`, `LOGIXIA_EXCEPTION_FILTER_OPTIONS`, `InjectLogger`, `LogMethod`, `createLoggerService` and their types are no longer exported from `logixia`. Import them from `logixia/nest`.

```diff
-import { LogixiaLoggerModule, LogixiaLoggerService, LogixiaExceptionFilter } from 'logixia';
+import { LogixiaLoggerModule, LogixiaLoggerService, LogixiaExceptionFilter } from 'logixia/nest';
```

Everything else stays on `logixia`. Because the root entry no longer touches NestJS, it now loads without `@nestjs/common` installed, which is what made this split necessary. See [NestJS](/guide/nestjs).

Search for these imports in your code base to find what to change:

```bash
grep -rnE "from 'logixia'" src | grep -E "Logixia(LoggerModule|LoggerService|ExceptionFilter)|InjectLogger|LogMethod|createLoggerService"
```

TypeScript users get a compile error for each missed import, so the build tells you where.

## Behaviour changes you may notice

None of these change the API, but they change what ends up in logs and responses.

### Redaction (1.13.3)

- Redaction is bounded: nesting past 32 levels becomes `[MaxDepth]`, more than 10,000 objects becomes `[MaxNodes]`, and strings over 16,384 characters are truncated before pattern scanning.
- Nested `Error` objects and `toJSON()` results are serialized and then redacted; URL credentials are stripped.
- If redaction throws, the entry carries `[RedactionFailed]` instead of the raw data.
- Control characters are stripped from messages, contexts and trace IDs in text output.
- `autoDetect` covers more header and cookie style names (`cookie`, `session`, `x-auth-token` and others).

### HTTP middleware (1.13.3)

- Default redacted headers were extended, and the new `redactQueryParams` option redacts sensitive query values in the logged URL.
- Bodies are pruned structurally before logging so path rules still match.

### Transports (1.13.3)

- Core fields (`timestamp`, `level`, `message`, `traceId` and similar) are authoritative: a payload key that collides with one is kept under a `data_` prefix instead of overwriting it.
- Text and CSV output escape control characters and line breaks.
- The file transport keeps at most `maxQueue` entries (default 10,000) in memory, applies `queuePolicy`, and creates files with mode `0600` and directories with `0700` by default (`fileMode`, `dirMode`).
- Database and analytics transports bound their retry buffers (`maxBufferSize`, default 10,000). The database transport keeps entries buffered through an outage and only drops entries the database rejected as bad data.
- Segment gained `userIdField`, and the CloudWatch transport gained EMF metrics options.

### Identifiers and exceptions (1.13.3)

- Incoming trace, correlation and request IDs are validated (1 to 128 characters from `[A-Za-z0-9._:-]`). Invalid values are replaced with a generated ID. If your clients send IDs with other characters, such as spaces or `/`, they will no longer be passed through.
- `LogixiaExceptionFilter` no longer returns the `debug` block (stack, service, duration) in any environment unless you set `exposeDebug: true`. `exposeCause: true` is additionally required to include the cause. Previously debug was returned everywhere except when `NODE_ENV` was `production`.
- `childFromRequest` ignores `X-Forwarded-For` unless `trustProxy: true`.
- Sampling bounds its trace-decision cache, and metrics cap label cardinality with `maxLabelSets` (default 1,000, overflow folded into `__overflow__`).
- `createLevelControlHandler` requires `Content-Type: application/json` on mutating requests (415 otherwise) and rejects bodies over 16 KB (413).
- The CLI escapes control characters in output and neutralizes spreadsheet formulas in CSV exports.

### 2.0.0 additions and fixes

- New `SlackTransport` and `DiscordTransport`. See [Slack and Discord](/guide/transports/slack-discord).
- The Datadog transport now sends logs to the v2 intake API. See [Datadog](/guide/transports/datadog).

### Tracing (2.0.2, published in 2.0.4)

- `LogixiaContext.run({ traceId })` also becomes the current `TraceContext` trace ID, so `getCurrentTraceId()`, the logger and the OpenTelemetry bridge agree.
- Request IDs are resolved the same way everywhere (header, then a usable `request.id`, then a generated UUID). Fastify's default counter IDs such as `req-1` are no longer used as trace IDs.
- The context helpers and the HTTP middleware accept `traceIdHeader`; the helpers have an opt-in `responseHeader` (off by default). A `traceId` returned from `enrich` is ignored.

### Secrets and browser (2.0.3 and 2.0.4)

- Transport credentials, the logger config and `BrowserRemoteTransport` options are hidden from serialization and inspection, and errors from requests and connections are scrubbed of credentials.
- `logixia/browser` no longer needs Node globals, so it runs on edge runtimes. `BrowserRemoteTransport` gained `silent` and `onError`, and reports delivery failures at most once a minute without URLs or error text. See [Browser and edge](/guide/browser-and-edge).

## Upgrade checklist

1. Install the latest 2.x.
2. Change NestJS imports to `logixia/nest`.
3. If you used `LogixiaExceptionFilter` and relied on debug output in non-production, pass `exposeDebug` (and `exposeCause`) explicitly.
4. Check any client that sends trace or correlation IDs with unusual characters.
5. Run your tests with `LOGIXIA_SILENT_INTERNAL=1` if logixia's stderr warnings clutter the output, and read them once: they point out misconfiguration such as an unknown level name.
