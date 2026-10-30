---
title: Typed logger and log schemas
description: Get autocomplete and compile-time checks for log fields with createTypedLogger, and catch missing or mistyped fields in development with defineLogSchema.
order: 16
---

# Typed logger and log schemas

By default the second argument of a log call is `Record<string, unknown>`, so a typo such as `ordreId` compiles and ships. `createTypedLogger` wraps a logger so that argument is checked against an interface you define.

```ts
import { createLogger, createTypedLogger } from 'logixia';

type OrderFields = {
  orderId: string;
  userId: string;
  amount?: number;
};

const logger = createLogger({ appName: 'orders' });
const orders = createTypedLogger<OrderFields>(logger);

await orders.info('order created', { orderId: 'ord_123', userId: 'u_9', amount: 49.9 });
// await orders.info('order created', { ordreId: 'ord_123' }); // compile error
```

::: tip Use a type alias
Define the fields with `type OrderFields = { ... }`. A TypeScript `interface` does not satisfy the `Record<string, unknown>` constraint and fails to compile.
:::

Fields are `Partial<TFields>`, so each call may supply any subset. The wrapper has `error` (string or `Error`), `warn`, `info`, `debug`, `verbose` and `trace`, and a `raw` property with the underlying logger. There is no runtime cost beyond a function call when no schema is attached.

## Runtime checks with a schema

`defineLogSchema` describes each field. When you pass the schema as the second argument to `createTypedLogger`, calls are validated outside production (`NODE_ENV !== 'production'`) and problems are printed as warnings; the entry is still logged.

```ts
import { createLogger, createTypedLogger, defineLogSchema } from 'logixia';

type OrderFields = {
  orderId: string;
  userId: string;
  amount?: number;
};

const schema = defineLogSchema<OrderFields>({
  orderId: { type: 'string', required: true },
  userId: { type: 'string', required: true },
  amount: {
    type: 'number',
    validate: (value) => ((value as number) < 0 ? 'must not be negative' : undefined),
  },
});

const orders = createTypedLogger<OrderFields>(createLogger({ appName: 'orders' }), schema);

await orders.info('order created', { orderId: 'ord_1', amount: -5 });
// warns: Required field "userId" is missing
// warns: Field "amount": must not be negative
```

Each field definition has:

| Property   | Description                                                                     |
| ---------- | ------------------------------------------------------------------------------- |
| `type`     | `'string'`, `'number'`, `'boolean'`, `'object'` or `'array'`.                   |
| `required` | Warn when the field is missing or `null`. Default `false`.                      |
| `validate` | Return a string to emit it as a warning, or `undefined` when the value is fine. |

Validation only runs when a data object is passed. A call with no second argument is not checked, so required fields are not reported in that case. In production, `schema.validate()` returns no warnings.

`createTypedLogger` accepts anything shaped like `LoggerLike`: promise-returning `error`, `warn`, `info` and `debug` methods and optionally `verbose` and `trace`. The synchronous browser logger does not match that shape.

## Typed custom levels

Typing for custom level methods comes from `createLogger()` itself: levels declared in `levelOptions.levels` become typed methods. See [Log levels](/guide/log-levels).
