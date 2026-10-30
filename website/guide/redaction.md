---
title: Redaction
description: Keep passwords, tokens and personal data out of logs with logixia redact - dot-path rules, regex patterns, autoDetect presets, exclusions and fail-closed behaviour.
order: 9
---

# Redaction

Set `redact` on the logger and logixia masks sensitive data in the payload, in nested errors and in the message string before any transport or plugin sees the entry.

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  redact: {
    paths: ['req.headers.authorization', '*.password', 'user.creditCard'],
    patterns: [/sk-[a-z0-9]{32,}/gi],
    censor: '[REDACTED]',
    autoDetect: 'conservative',
  },
});

await logger.info('login', { user: { name: 'ada', creditCard: '4111 1111 1111 1111' } });
// user.creditCard is replaced with [REDACTED]
```

## Options

| Option         | Type                                        | Default        | Description                                                |
| -------------- | ------------------------------------------- | -------------- | ---------------------------------------------------------- |
| `paths`        | `string[]`                                  | none           | Dot-notation paths whose values are replaced.              |
| `excludePaths` | `string[]`                                  | none           | Paths exempt from pattern and `autoDetect` value scanning. |
| `patterns`     | `RegExp[]`                                  | none           | Regexes applied to string values; each match is replaced.  |
| `censor`       | `string`                                    | `'[REDACTED]'` | The replacement text.                                      |
| `autoDetect`   | `boolean \| 'conservative' \| 'aggressive'` | off            | Built-in secret and PII rules, added to your own.          |

## Path syntax

Paths are dot-separated and matched case-insensitively against the full path of each value.

| Pattern         | Matches                                           |
| --------------- | ------------------------------------------------- |
| `password`      | A top-level `password`.                           |
| `user.password` | `password` directly under `user`.                 |
| `*.token`       | `token` one level down, under any key.            |
| `req.headers.*` | Every direct child of `req.headers`.              |
| `**.password`   | `password` at any depth, including the top level. |
| `req.**`        | `req` and everything below it.                    |

`*` matches exactly one segment; `**` matches any number, including zero.

## Patterns

`patterns` run over string values (and over the log message), so they catch secrets that sit in free text:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  redact: { patterns: [/Bearer\s+\S+/gi] },
});

await logger.error('upstream rejected Bearer eyJhbGciOi.payload.sig');
// message: upstream rejected [REDACTED]
```

Only `patterns` apply to the message string; path rules need an object to walk.

## autoDetect

`autoDetect: true` (or `'conservative'`) adds:

- patterns for JWTs, `Bearer` values, `sk-` / `pk-` / `api-` / `key-` / `secret-` / `token-` prefixed keys, AWS access key IDs and AWS secret access keys;
- name-based rules (`**.<name>`) for common secret field names: `password`, `passwd`, `secret`, `token`, `apiKey`, `api_key`, `accessToken`, `access_token`, `refreshToken`, `refresh_token`, `authorization`, `credentials`, `privateKey`, `private_key`, `clientSecret`, `client_secret`, `cookie`, `set-cookie`, `x-api-key`, `session`, `proxy-authorization`, `x-auth-token`, `x-access-token` and the AWS secret key names.

`'aggressive'` adds patterns for email addresses, US Social Security numbers, card numbers, US phone numbers and IPv4 addresses, plus field names such as `email`, `phone`, `ssn`, `dob`, `creditCard`, `cardNumber`, `cvv` and `ipAddress`. Aggressive matching is blunt: a long run of digits can look like a card or phone number. Use `excludePaths` for identifiers that trip it:

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  redact: { autoDetect: 'aggressive', excludePaths: ['**.vendorRefId', '**.traceId'] },
});

await logger.info('synced', { vendorRefId: '1234567890123', email: 'ada@example.com' });
// vendorRefId is kept, email is redacted
```

If a field matches both `paths` and `excludePaths`, `paths` wins.

## What is covered

- Nested objects and arrays, class instances, `toJSON()` results and nested `Error` objects (name, message, stack and `cause` chain are serialized and then scanned).
- Circular references become `[Circular]`. The original object is never modified.
- The log message string, for `patterns` and `autoDetect` patterns.
- HTTP request headers and query parameters have their own lists in the [HTTP logging](/guide/http-logging) middleware.

## Limits and failure behaviour

Redaction is bounded so a hostile payload cannot stall the process:

- nesting deeper than 32 levels becomes `[MaxDepth]`; more than 10,000 objects in one pass becomes `[MaxNodes]`;
- strings longer than 16,384 characters are cut before pattern scanning and the tail is dropped, never logged unscanned;
- secret patterns use bounded quantifiers so scanning stays linear.

If redaction itself throws, logixia fails closed: the payload is replaced with `{ redaction: '[RedactionFailed]' }` and the message with `[RedactionFailed]`, and the raw data is not emitted.

## Use it outside the logger

```ts
import { applyRedaction, redactObject } from 'logixia';

const safe = applyRedaction({ user: { password: 'x' } }, { paths: ['**.password'] });
console.log(safe); // { user: { password: '[REDACTED]' } }

const copy = redactObject({ token: 't' }, { paths: ['token'] });
console.log(copy);
```

Both return new objects and never mutate their input.

::: tip Redact at the logger, not in each transport
Because redaction runs before transports and plugins, one `redact` block covers file, database, cloud and analytics outputs together. See [Security](/guide/security) for the other protections around secrets.
:::
