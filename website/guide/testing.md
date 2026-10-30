---
title: Testing with the mock logger
description: Assert on log output in Jest or Vitest with logixia/testing createMockLogger - record calls, match messages and fields, and verify that nothing was logged.
order: 21
---

# Testing with the mock logger

`logixia/testing` exports `createMockLogger()`, a dependency-free logger that records every call instead of writing it anywhere. It implements the same interface as a real logger, so you can pass it wherever your code expects one.

```ts
import { createMockLogger } from 'logixia/testing';
import type { IBaseLogger } from 'logixia';

async function processOrder(orderId: string, logger: IBaseLogger): Promise<void> {
  await logger.info('order processed', { orderId });
}

describe('processOrder', () => {
  it('logs the order', async () => {
    const mock = createMockLogger();

    await processOrder('123', mock.logger);

    mock.expectLog('info', 'order processed');
    mock.expectLog('info', { orderId: '123' });
    mock.expectNoLog('error');
  });
});
```

Design your code to receive a logger as a parameter or through dependency injection, and the test needs no mocking library.

## The mock instance

`createMockLogger(options?)` returns an object with:

| Member                         | Description                                            |
| ------------------------------ | ------------------------------------------------------ |
| `logger`                       | The logger to hand to your code (`IBaseLogger`).       |
| `calls`                        | Every recorded call, in order.                         |
| `getCalls(level?)`             | Calls for one level (case-insensitive), or all.        |
| `getLastCall(level?)`          | The most recent call, optionally for one level.        |
| `expectLog(level, matcher?)`   | Throws unless at least one call at that level matches. |
| `expectNoLog(level, matcher?)` | Throws if any call at that level matches.              |
| `reset()`                      | Clear recorded calls. Call it between tests.           |

Options: `context` sets the `context` of recorded entries and is returned by `getContext()`. `silent` is accepted for compatibility; the mock never prints.

Each `MockLogCall` has `level`, `message`, optional `data` and an `entry` with the same values plus `context`. Calling `error(err)` with an `Error` records the error's message, and adds `error: { message, stack }` to `data`.

## Matchers

`expectLog` and `expectNoLog` take an optional matcher. Without one, any call at that level matches.

| Matcher  | Matches when                                                                                             |
| -------- | -------------------------------------------------------------------------------------------------------- |
| `string` | The message equals it exactly.                                                                           |
| `RegExp` | The message matches.                                                                                     |
| function | It returns `true` for the `MockLogCall`.                                                                 |
| object   | Every key matches: `message` and `level` read the call, other keys read `data`. Values can be `RegExp`s. |

```ts
import { createMockLogger } from 'logixia/testing';

const mock = createMockLogger();

await mock.logger.error(new Error('card declined'), { orderId: 'o1', attempt: 2 });
await mock.logger.warn('slow query', { ms: 812 });

mock.expectLog('error', /declined/);
mock.expectLog('error', { message: 'card declined', orderId: 'o1' });
mock.expectLog('warn', (call) => Number(call.data?.['ms']) > 500);

console.log(mock.getLastCall('warn')?.data);
mock.reset();
```

A failed expectation throws an `Error` that lists the matcher and every recorded call, so the cause is visible in the test output. Because it throws, it works with any test runner.

## Child loggers

`mock.logger.child(context)` returns a separate mock whose calls are not added to the parent's `calls`. If your code creates child loggers, either pass in the child you will assert on, or assert on something your code exposes. For example:

```ts
import { createMockLogger } from 'logixia/testing';

const mock = createMockLogger();
const child = mock.logger.child('Payments');

await child.info('charged');
console.log(mock.calls.length); // 0, the child records elsewhere
```

## Testing with a real logger

When you want to check real formatting or transport behaviour, use `silent: true` on a real logger to mute output, or a [custom transport](/guide/transports/custom) that collects entries in an array. Set `LOGIXIA_SILENT_INTERNAL=1` to hide logixia's own stderr diagnostics in test output.

```ts
import { createLogger } from 'logixia';

const entries: string[] = [];

const logger = createLogger({
  appName: 'test',
  transports: {
    custom: [
      {
        name: 'collector',
        write(entry) {
          entries.push(`${entry.level}:${entry.message}`);
        },
      },
    ],
  },
});

await logger.info('hello');
console.log(entries); // ['info:hello']
```
