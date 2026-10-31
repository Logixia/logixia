---
title: Security
description: 'How logixia protects secrets and your supply chain: redaction, hidden transport credentials, validated IDs, escaped output, npm provenance and reporting.'
order: 22
---

# Security

Logs are a common place for secrets and attacker-controlled text to end up. This page lists what logixia does about it, what it leaves to you, and how its releases are built.

## Keep secrets out of log data

- **Redact at the logger.** `redact.paths`, `patterns` and `autoDetect` mask values before any transport or plugin sees them, and fail closed if redaction throws. See [Redaction](/guide/redaction).
- **HTTP middleware** redacts sensitive headers (`authorization`, `cookie`, `x-api-key` and more) and query parameters (`token`, `access_token`, `password`, `signature`, presigned-URL signatures and more) by default. `redact.queryParams` adds names for the NestJS exception filter and trace middleware. See [HTTP logging](/guide/http-logging).
- **Bodies** are only logged when you turn on `logBody`, and pass through your redaction rules.
- Do not log secrets on purpose. Redaction is a safety net that works by names and patterns; it cannot know that an arbitrary string is sensitive.

## Transport credentials stay hidden

API keys, tokens, connection strings and passwords given to transports, to the logger config, and to `BrowserRemoteTransport` (`headers`, `url`) are stored behind non-enumerable properties. If you print a transport with `console.log`, `JSON.stringify` or `util.inspect`, secret-looking fields show as `[REDACTED]` and URLs lose their credentials, query and fragment. Error messages from failed requests and database connections are scrubbed the same way. Load credentials from environment variables or a secrets manager rather than source files.

## Untrusted identifiers

Trace IDs, correlation IDs, request IDs and origin service names often come from clients. logixia accepts an incoming ID only if it is 1 to 128 characters from `[A-Za-z0-9._:-]`; anything else (too long, control characters, newlines, spaces inside) is replaced by a generated ID. This prevents log injection through headers and keeps unbounded text out of every line. See [Tracing](/guide/tracing). At the edge, you can also stop trusting client-supplied correlation IDs with `trustIncoming: false`, and leave `trustProxy` off in `childFromRequest` unless a proxy you control sets `X-Forwarded-For`.

## Output is escaped

Control characters in messages, contexts, trace IDs and custom level names are stripped in text output, and line breaks cannot forge extra lines in the console and file transports. JSON output is escaped by the serializer. The `logixia` [CLI](/guide/cli) replaces control characters with visible escapes when it prints log content, so a crafted entry cannot drive your terminal, and its CSV export prefixes cells that start with `=`, `+`, `-`, `@` or a tab so spreadsheets do not execute them.

## Files and memory

- The file transport creates log files with mode `0600` and directories with mode `0700` by default. Change them with `fileMode` and `dirMode`.
- Buffers in the file, database, analytics and browser transports are bounded, so an outage cannot grow memory without limit. Overflow is dropped and counted. See each transport page.
- Redaction itself is bounded in depth, node count and string length.

## Operational endpoints

- `createLevelControlHandler()` has no authentication. Mount it only behind your own auth on an internal route. It requires `Content-Type: application/json` and caps the body at 16 KB. See [Log levels](/guide/log-levels).
- The `/metrics` endpoint exposes label values taken from your log payloads. Keep labels low-cardinality and non-sensitive. See [Metrics](/guide/metrics).
- `LogixiaExceptionFilter` hides stack traces and causes from responses unless you enable `exposeDebug` and `exposeCause`. Leave them off in production. See [NestJS](/guide/nestjs).

## Supply chain

- **Three runtime dependencies**: `commander`, `fast-json-stringify` and `picocolors`. NestJS, Express, `reflect-metadata` and database drivers are optional and only loaded if you use them.
- **No install scripts.** The published package declares no `preinstall`, `install` or `postinstall` script, so installing it runs no code from logixia.
- **Provenance.** Releases are published to npm with provenance, so each version links to the commit and workflow run that built it. Check with `npm audit signatures`.
- **Trusted publishing.** The publish job authenticates to npm with GitHub OIDC trusted publishing; there is no long-lived npm token. It publishes a tarball built earlier in the pipeline, after verifying its SHA-256, with `--ignore-scripts`.

## Reporting a vulnerability

Please do not open a public issue for a security problem. Report it privately through [GitHub's private vulnerability reporting](https://github.com/Logixia/logixia/security/advisories/new) and include the version, a minimal reproduction and the impact you expect. You should get a reply within 3 working days. Once a fix is released, the advisory is published with credit to the reporter unless you ask otherwise.

Only the latest minor release gets security fixes. See [SECURITY.md](https://github.com/Logixia/logixia/blob/main/SECURITY.md).
