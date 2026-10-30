---
layout: home
title: 'logixia: structured logging, request tracing and export for Node.js'
titleTemplate: false
description: 'Structured logging, request tracing and multi-destination export for Node.js, NestJS and the edge, in one TypeScript-first library.'
---

<div class="vp-raw">
  <HomeHero />
  <HomeIntegrations />
  <HomeBento />
</div>

<div class="lx-section">

## Quick start

```bash
npm install logixia
```

```ts
import { createLogger } from 'logixia';

const logger = createLogger({
  appName: 'api',
  environment: 'production',
  traceId: true,
  redact: { paths: ['**.password', '**.authorization'], autoDetect: true },
  transports: {
    console: { format: 'json' },
    file: { filename: 'app.log', dirname: './logs', maxSize: '50MB', maxFiles: 14 },
  },
});

await logger.info('Order created', { orderId: 'ord_42', password: 'hunter2' });
// password is written as "[REDACTED]", a traceId is attached,
// and the entry goes to the console and the rotating file.
```

Continue with the [getting started guide](/guide/getting-started).

## One library instead of five

A typical Node.js service assembles its logging from several packages. logixia ships those pieces together and tested against each other, so there is less to wire up and keep in sync.

| You usually assemble                           | In logixia                                         |
| ---------------------------------------------- | -------------------------------------------------- |
| A JSON logger                                  | `createLogger`, with text, JSON and CSV formats    |
| An HTTP request logger and trace-ID middleware | Express, Fastify and NestJS helpers, `traceparent` |
| Redaction configuration                        | `redact: { paths, patterns, autoDetect }`          |
| Log shippers for files, databases and clouds   | Built-in transports with batching and rotation     |
| OpenTelemetry glue code                        | Trace correlation and an OTLP log transport        |

You can still use logixia next to other tools. It is one more option, not a requirement to replace anything.

## Works with your framework

::: code-group

<<< @/../examples/website/express.ts [Express]

<<< @/../examples/website/fastify.ts [Fastify]

<<< @/../examples/website/nestjs.ts [NestJS]

<<< @/../examples/website/cloudflare-worker.ts [Cloudflare Worker]

:::

<div class="home-cta">

## Ready to try it?

Install the package, add a logger, and ship logs where you need them.

[Read the guide](/guide/getting-started){.cta-primary}
[Browse articles](/articles/){.cta-secondary}

</div>

</div>
