---
title: 'How to Redact Sensitive Data in Node.js Logs'
description: 'Keep tokens, cookies and PII out of Node.js logs. Path vs pattern redaction, error and URL gotchas, regex pitfalls, and a working logixia config.'
date: 2026-10-28
tags: [security, redaction, pii, nodejs, logging]
---

# How to Redact Sensitive Data in Node.js Logs

**TL;DR:** To redact sensitive data in Node.js logs, mask by _field path_ for data you know is sensitive (`req.headers.authorization`, `**.password`) and by _pattern_ for secrets that show up inside free text (bearer tokens, API keys). Do it inside the logger, before any transport sees the entry, and test it with real payloads. logixia does both with one `redact` option; this article explains what each part catches and, just as important, what it does not.

Logs are the place secrets leak most often, because nobody designs them as a data store. A debug line that prints an Axios error will happily include the `Authorization` header of the failed request. A support engineer pastes a log search into a ticket. A third-party log vendor now holds a copy of every session cookie you ever logged. Redaction is the cheap control that stops this at the source.

## What should you redact from logs?

Start with a short, boring list:

- **Credentials:** `password`, `token`, `access_token`, `refresh_token`, `apiKey`, `client_secret`, private keys.
- **Request secrets:** the `Authorization`, `Cookie`, `Set-Cookie` and `x-api-key` headers, and query parameters such as `?token=`, `?code=` and `?signature=`.
- **Payment and identity data:** card numbers, CVV, national ID numbers.
- **Personal data (PII):** emails, phone numbers, IP addresses and dates of birth, depending on your privacy obligations.

Two things are easy to forget. First, secrets also arrive _inside strings_: `"Request failed: Bearer eyJhbGciOi..."`. Second, they arrive inside **errors**: a rejected HTTP client call serializes its whole request config.

## Path-based vs pattern-based redaction

The two approaches catch different failures, and you want both.

**Path-based redaction** masks a value because of _where it lives_. It is precise and cheap: `user.password` is redacted whatever it contains. Its weakness is that you must know the path in advance, so a new field named `pwd` slips through until someone adds it.

**Pattern-based redaction** masks a value because of _what it looks like_: a JWT, a `Bearer ...` string, an `sk_live_...` key. It catches secrets that land in unexpected fields or in the message text. Its weaknesses are false positives (an aggressive phone-number regex will happily match an order ID) and cost (a regex runs against every string in every log call).

## How do I redact logs with logixia?

Redaction is **opt-in**: nothing is masked unless you pass a `redact` config. The config accepts `paths`, `patterns`, `excludePaths`, `censor` and `autoDetect`.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  transports: { console: { format: 'json', colorize: false } },
  redact: {
    paths: ['req.headers.authorization', '**.password', 'user.ssn'],
    patterns: [/sk_live_[A-Za-z0-9]{8,}/g],
    censor: '[REDACTED]',
    autoDetect: true,
  },
});

await logger.info('login attempt', {
  req: { headers: { Authorization: 'Bearer abc.def.ghi', accept: 'application/json' } },
  user: { name: 'Ada', password: 'hunter2', ssn: '123-45-6789' },
  note: 'retrying with sk_live_ABCDEFGH12',
});
```

Running this prints (trimmed):

```json
{
  "level": "info",
  "message": "login attempt",
  "req": { "headers": { "Authorization": "[REDACTED]", "accept": "application/json" } },
  "user": { "name": "Ada", "password": "[REDACTED]", "ssn": "[REDACTED]" },
  "note": "retrying with [REDACTED]"
}
```

Some details worth knowing, all verified against the current source:

- **Paths** use dot notation. `*` matches exactly one segment and `**` matches any depth, including zero segments, so `**.password` catches both a top-level `password` and `a.b.c.password`. Matching is case-insensitive, which is why `Authorization` matched `req.headers.authorization` above.
- **Arrays** work: `list.0.password` and the index-free `list.password` both match.
- **Patterns** apply to string values anywhere in the payload _and_ to the log message itself, so ``logger.info(`Auth: Bearer ${token}`)`` is still masked. Path rules cannot apply to a bare message string; only patterns run there.
- **`autoDetect: true`** (or `'conservative'`) adds JWTs, `Bearer` tokens, `sk-`/`pk-`/`api-` style keys, AWS access key IDs, and masks common secret field names such as `password`, `token`, `secret`, `authorization`, `cookie` and `apiKey`. **`'aggressive'`** also adds emails, card numbers, US SSNs, US phone numbers and IPv4 addresses.
- **`excludePaths`** exempts fields from _pattern_ scanning, which is how you stop an aggressive phone-number pattern from mangling a vendor reference ID (`excludePaths: ['**.vendorRefId']`). It does not override `paths`: a field matched by both is still censored.
- Redaction runs **before** plugins and transports, so console, file, Datadog and every other destination receive the masked entry. See [Security](/guide/security) for how transport credentials are protected separately.

For the full option list, see the [redaction guide](/guide/redaction).

## Are errors and URLs redacted?

Errors: yes. When you log an `Error`, logixia serializes it (own properties and the `cause` chain) and walks the result, so both the message and nested data like `config.headers.authorization` are covered:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  redact: { paths: ['**.authorization'], patterns: [/sk_live_[A-Za-z0-9]{8,}/g] },
});

const upstream = Object.assign(new Error('upstream failed for sk_live_ABCDEFGH12'), {
  config: { headers: { authorization: 'Bearer zzz' } },
});

await logger.error(upstream);
```

URLs are where people get caught. A `URL` _object_ has its username and password stripped. A URL **string** in a payload, however, is only touched by your patterns: a `?token=abc123` inside it survives unless you add a pattern for it. Test this rather than assuming:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  redact: {
    // mask the value of sensitive query parameters in any URL string
    patterns: [/([?&](?:token|access_token|code|signature)=)[^&\s]+/gi],
    censor: '[REDACTED]',
  },
});

await logger.info('callback received', { url: 'https://example.com/cb?token=abc123&x=1' });
```

Note that a replace-with-censor pattern swaps the _whole match_, including the `?token=` prefix, so the output reads `https://example.com/cb[REDACTED]&x=1`. That is fine for security; if you want the parameter name preserved, mask on the path side or sanitize the URL before logging.

The HTTP middleware handles this for you in its own log lines: `createExpressMiddleware` redacts a default set of headers (`authorization`, `cookie`, `set-cookie`, `x-api-key`, `proxy-authorization`, `x-auth-token`, `x-access-token`, `x-csrf-token`, `x-amz-security-token`) and query parameters (`token`, `access_token`, `refresh_token`, `code`, `password`, `secret`, `api_key`, `apikey`, `key`, `signature`, `sig`, `auth`), and you can extend both lists:

```ts
import { createLogger } from 'logixia';
import { createExpressMiddleware } from 'logixia/middleware';

const logger = createLogger({ appName: 'api', redact: { autoDetect: true } });

export const httpLogger = createExpressMiddleware(logger, {
  redactHeaders: ['x-session-id'],
  redactQueryParams: ['invite'],
  logBody: true, // body is captured, size-capped, and still passes through logger redaction
});
```

See [HTTP request logging](/guide/http-logging) for details.

## What are the pitfalls of log redaction?

**1. Forgetting the `g` flag.** `String.prototype.replace` with a non-global regex replaces only the first match. In a test, `/acct_\d+/` masked `acct_1` but left `acct_2` in the same string. Always write `/…/g`.

**2. Regular expression denial of service (ReDoS).** Your patterns run on every string in every log call, often on attacker-controlled input such as a header or request body. A pattern with nested quantifiers like `/(a+)+$/` can take exponential time on a crafted string and stall your event loop. logixia's built-in patterns use bounded quantifiers so scanning stays linear, and it caps scanning at 16,384 characters per string, which limits the damage. It cannot make an unsafe custom regex safe. Keep custom patterns simple and anchored on a literal prefix (`sk_live_`), and avoid `(.*)+`-style constructs.

**3. Truncation of long strings.** Strings over 16,384 characters are truncated before scanning, and the tail is dropped, not emitted unscanned. The entry gets a marker like `…[truncated 20019 unscanned chars]`. That is the safe choice (a secret past the limit cannot leak), but it means a huge logged blob loses data. Do not log whole payloads as strings.

**4. Depth and size limits.** Redaction walks at most 32 levels deep and 10,000 objects per call, replacing the rest with `[MaxDepth]` or `[MaxNodes]`. Circular references become `[Circular]`. If redaction itself throws, logixia fails closed and logs `[RedactionFailed]` instead of the raw payload.

**5. Aggressive auto-detection has false positives.** Digit runs match phone and card patterns. Use `excludePaths` for known-safe identifiers and review a sample of real logs after enabling it.

**6. Redaction is not a substitute for not logging.** The best way to protect a password is never to put it in a log call. Redact as a safety net, not as a design.

## How do I test that redaction works?

Treat redaction like any security control and put it under test. logixia exports `applyRedaction`, so you can assert on the exact output without spinning up a logger:

```ts
import { strict as assert } from 'node:assert';
import { applyRedaction } from 'logixia';

const config = { paths: ['**.password'], patterns: [/sk_live_[A-Za-z0-9]{8,}/g] };

const out = applyRedaction(
  { user: { password: 'hunter2' }, note: 'key sk_live_ABCDEFGH12 here' },
  config
);

assert.deepEqual(out, {
  user: { password: '[REDACTED]' },
  note: 'key [REDACTED] here',
});
```

Add a fixture for each secret type you care about, and one test that logs a realistic failing HTTP client error.

## Key takeaways

- Use **paths** for known-sensitive fields and **patterns** for secrets inside strings; enable `autoDetect` as a baseline.
- Redaction in logixia is opt-in and runs before every transport.
- URL strings, long strings and custom regexes are the usual gaps; test them.
- Always use the `g` flag, and keep custom regexes ReDoS-safe.

## FAQ

**How do I mask passwords in Node.js logs?** Add `**.password` to `redact.paths` (and `autoDetect: true` for the common credential field names). The password value is replaced with `[REDACTED]` wherever it appears in the payload.

**Does logixia redact the `Authorization` header automatically?** The HTTP logging middleware redacts it by default. For your own log calls, add `req.headers.authorization` (or `**.authorization`) to `redact.paths`, or use `autoDetect`, which includes `authorization` among its field names.

**Does redaction slow logging down?** There is work per call when `redact` is configured, since values are walked and strings scanned; with no `redact` config the redaction path is skipped entirely. Measure with your own payloads and patterns.

**Can I redact PII like emails?** Yes: use `autoDetect: 'aggressive'`, or `**.email` in `paths`, or an email regex in `patterns`. Expect some false positives with the aggressive preset and tune with `excludePaths`.
