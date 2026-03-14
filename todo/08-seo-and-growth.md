# 08 — npm SEO & Organic Growth

> Logixia currently has **0 keywords in package.json**, a generic description,
> and no GitHub topics. This is leaving free discoverability on the table.
> Everything here is low-effort, high-return.

---

## SEO-01 🟠 `package.json` — description and keywords need a complete rewrite

### Current state
```json
{
  "description": "Enterprise-grade TypeScript logging library with comprehensive transport system, database integration, and advanced log management capabilities",
  "keywords": []
}
```

Zero keywords means **zero npm search hits** for anything that isn't the exact package name.

### Fix — updated `package.json` fields

```json
{
  "description": "TypeScript logger with custom log levels, multi-transport (console, file, DB, analytics), NestJS module, built-in search, request tracing, and zero-dep OpenTelemetry support",
  "keywords": [
    "logger",
    "logging",
    "typescript",
    "typescript-logger",
    "nestjs",
    "nestjs-logger",
    "nestjs-logging",
    "nestjs-module",
    "winston-alternative",
    "pino-alternative",
    "structured-logging",
    "json-logging",
    "custom-log-levels",
    "log-levels",
    "request-tracing",
    "trace-id",
    "opentelemetry",
    "w3c-trace-context",
    "multi-transport",
    "console-transport",
    "file-transport",
    "log-rotation",
    "database-logging",
    "mongodb-logger",
    "postgresql-logger",
    "analytics-logging",
    "datadog",
    "mixpanel",
    "segment",
    "log-search",
    "log-analysis",
    "log-aggregation",
    "nodejs",
    "bun",
    "express",
    "microservices",
    "distributed-tracing",
    "observability",
    "developer-tools",
    "enterprise-logging"
  ]
}
```

Also add or update:
```json
{
  "homepage": "https://github.com/webcoderspeed/logixia#readme",
  "repository": {
    "type": "git",
    "url": "https://github.com/webcoderspeed/logixia.git"
  },
  "bugs": {
    "url": "https://github.com/webcoderspeed/logixia/issues"
  }
}
```

---

## SEO-02 🟠 GitHub repository — description, topics, and website URL

### Recommended GitHub repo description (160 char max)
```
TypeScript logger with custom levels, NestJS module, multi-transport (file/DB/analytics), built-in search, request tracing, and OpenTelemetry support.
```

### Recommended GitHub topics (add in Settings → About → Topics)
```
typescript  logger  logging  nestjs  nodejs  structured-logging
custom-log-levels  request-tracing  opentelemetry  log-rotation
file-logging  database-logging  datadog  mixpanel  segment
log-search  multi-transport  express  observability  developer-tools
```

### Website URL
Set to npm package page: `https://www.npmjs.com/package/logixia`
Or your blog post / docs site if you have one.

### Social preview image
Create a 1280×640 banner image for the GitHub repo (Settings → Social preview).
Use Figma or Canva. Should show:
- Library name: **logixia**
- Tagline: "Structured logging that scales"
- Key feature icons: custom levels, NestJS, multi-transport, search
- Dark theme matching typical developer preference

---

## SEO-03 🟡 npm README badges — builds trust and signals active maintenance

Add to the top of `README.md`:

```markdown
[![npm version](https://img.shields.io/npm/v/logixia.svg)](https://www.npmjs.com/package/logixia)
[![npm downloads](https://img.shields.io/npm/dm/logixia.svg)](https://www.npmjs.com/package/logixia)
[![CI](https://github.com/webcoderspeed/logixia/actions/workflows/ci.yml/badge.svg)](https://github.com/webcoderspeed/logixia/actions)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue.svg)](https://www.typescriptlang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
```

Once you have test coverage set up (see `03-testing.md`):
```markdown
[![Coverage](https://codecov.io/gh/webcoderspeed/logixia/branch/main/graph/badge.svg)](https://codecov.io/gh/webcoderspeed/logixia)
```

---

## SEO-04 🟡 Create comparison table vs winston / pino / bunyan

The most common search query before adopting a logging library is:
**"typescript logger comparison"** / **"nestjs logger"** / **"winston vs pino vs logixia"**.

Add to README (after the Quick Start section):

```markdown
## Why logixia over winston/pino?

| Feature | logixia | winston | pino |
|---------|---------|---------|------|
| TypeScript-first (generics, zero `any`) | ✅ | ⚠️ types via @types | ⚠️ partial |
| Custom business log levels with full type safety | ✅ | ⚠️ untyped | ❌ |
| NestJS module (forRoot / forRootAsync / forFeature) | ✅ | requires wrapper | requires wrapper |
| Built-in request trace ID (AsyncLocalStorage) | ✅ | ❌ | via pino-http |
| Built-in log search & analysis | ✅ | ❌ | ❌ |
| Database transports (MongoDB, PG, MySQL, SQLite) | ✅ | via plugins | ❌ |
| Analytics transports (Datadog, Mixpanel, Segment) | ✅ | via plugins | via plugins |
| File rotation built-in | ✅ | via winston-daily-rotate-file | ✅ |
| CLI tool for log search/analysis | ✅ | ❌ | ❌ |
| Bundle size (approx) | ~45 kB | ~150 kB | ~15 kB |
```

---

## GROWTH-01 🟡 LinkedIn post — announce to the TypeScript community

Use the same playbook as reixo. The hook angle for logixia:

**Option A — "Custom log levels" angle:**
> "I needed a log level called `payment`. Not `info`. Not `error`. `payment`.
> So I could search production logs by business domain, not severity.
> Here's why I built my own TypeScript logger."

**Option B — "NestJS missing feature" angle:**
> "NestJS's built-in logger gives you: info, warn, error, debug, verbose.
> That's it. No trace IDs. No file output. No database persistence.
> I spent 3 projects wiring up winston from scratch before building this."

**Option C — "Everything in one" angle:**
> "I counted 6 npm packages for a single logging setup:
> winston + winston-transport-mongodb + winston-daily-rotate-file +
> @nestjs/winston + pino-http + elastic-apm-node
> I built logixia so it's 1 package instead."

LinkedIn post rules (same as reixo):
- Blog link goes in **first comment** (not post body — 60% reach penalty)
- End with an open question
- 3-5 hashtags: `#TypeScript #NestJS #NodeJS #OpenSource #DeveloperExperience`

---

## GROWTH-02 🟡 Dev.to / Hashnode article

Write a 1 500-word article titled:
**"Building a production NestJS logger with custom business log levels, trace IDs, and DB persistence"**

Outline:
1. The problem: NestJS logger is a toy
2. Winston works but needs 4 packages
3. Introducing logixia — show the 30-second setup
4. Custom levels demo: `logger.payment('charged $99')`, `logger.order('placed')`
5. Trace ID magic: every request log tied together automatically
6. Search: `logixia search --query "payment error" --last 1h`
7. Where to go next

Articles on Dev.to with NestJS in the title get 2 000–20 000 views organically.

---

## GROWTH-03 🟡 Reddit posts

**r/typescript** — "I built a TypeScript logger with generics-based custom log levels"
- Lead with the type safety angle
- Show the `createLogger<'payment' | 'order'>()` syntax
- Ask: "What's your current logging setup?"

**r/node** — "Open-sourced a Node.js logger with built-in log search, CLI, and DB transports"
- Lead with the breadth angle
- Show the CLI demo
- Ask: "Do you use a custom transport for your logs?"

**r/nestjs** — "NestJS logging module with forRoot/forRootAsync, trace IDs, and multi-transport"
- Lead with the NestJS pain point
- Show `LogixiaLoggerModule.forRoot()` one-liner
- Ask: "How are you handling trace IDs in NestJS?"

---

## GROWTH-04 🟢 Show HN on Hacker News

**Title:** "Logixia – TypeScript logger with custom business log levels, NestJS module, and built-in search"

**Body:**
```
Hey HN,

I built Logixia after repeatedly wiring up the same logging stack across projects:
- winston/pino for transport
- morgan/pino-http for request logging
- cls-hooked/AsyncLocalStorage for trace IDs
- a custom NestJS wrapper

Logixia is a single package that bundles all of this. The main differentiator is
truly typed custom log levels:

  const logger = createLogger({ customLevels: { payment: { color: 'green' } } });
  logger.payment('charged $99');   // TypeScript knows this exists

Other features: file rotation, DB transports (Mongo/PG/MySQL/SQLite),
analytics (Datadog/Mixpanel/Segment), a CLI for log search, and a NestJS
module with forRoot/forRootAsync.

GitHub: https://github.com/webcoderspeed/logixia
npm: logixia

Would love feedback on the API design — especially the custom levels approach.
```

---

## GROWTH-05 🟢 Add `logixia` as an alternative on competing packages' GitHub

Many comparison lists and alternative registries exist:
- **awesome-nodejs** — open a PR to add logixia under "Logging"
- **openbase.com** — submit logixia
- **npmcompare.com** — it auto-indexes, just ensure keywords are right
- **bestofjs.org** — submit for listing

---

## GROWTH-06 🟢 FUNDING.yml — enable GitHub Sponsors

```yaml
# .github/FUNDING.yml
github: webcoderspeed
```

Shows a "Sponsor" button on the repo. Even if no one sponsors immediately,
it signals this is a serious maintained project.
