# Logixia — Improvement Plan Overview

> Generated after full codebase audit. Every item below has a dedicated
> deep-dive file. Work through them in priority order.

---

## Priority Matrix

| Priority | Label            | Meaning                                                           |
| -------- | ---------------- | ----------------------------------------------------------------- |
| 🔴 P0    | **Blocker**      | Breaks installation or produces incorrect behaviour in production |
| 🟠 P1    | **Critical**     | Causes data loss, silent failures, or major type-safety holes     |
| 🟡 P2    | **Important**    | Affects production reliability, performance, or security          |
| 🟢 P3    | **Nice to have** | DX, ecosystem growth, organic reach                               |

---

## Quick Summary by File

| File                      | What it covers                                                                               |
| ------------------------- | -------------------------------------------------------------------------------------------- |
| `01-critical-bugs.md`     | Self-dep in package.json, private-method call in factory, console.log leaks, silent `.catch` |
| `02-type-safety.md`       | All `any` types, weak index signatures, untyped DB connection, dynamic method generation     |
| `03-testing.md`           | Full test plan — currently <5 % coverage, 323 tests needed                                   |
| `04-missing-features.md`  | Compression stub, real NLP, Prometheus metrics, log sampling, config-file support            |
| `05-performance.md`       | O(n) search, unbounded caches, stream leak, batch-flush bottleneck                           |
| `06-security.md`          | Credentials in config, no input validation, path traversal in file transport                 |
| `07-dx-and-api.md`        | Config duplication, static module state, missing `forFeature` cleanup, schema validation     |
| `08-seo-and-growth.md`    | npm description, keywords, GitHub topics, LinkedIn/HN growth playbook                        |
| `09-examples-and-docs.md` | 13 examples audit, missing JSDoc, architecture diagram, migration guide                      |

---

## Blocker Checklist (fix before next release)

- [ ] 🔴 Remove `"logixia": "^1.0.3"` self-reference from `dependencies` in `package.json`
- [ ] 🔴 Fix private `log()` method call inside `createLogger` factory (`logitron-logger.ts:597`)
- [ ] 🟠 Replace all `console.log` / `console.error` inside library source with proper fallback logging
- [ ] 🟠 Replace all silent `.catch(console.error)` in `LogixiaLoggerService` with structured handling
- [ ] 🟠 Type `DatabaseTransport.connection` — remove the `: any`
- [ ] 🟠 Type the dynamic index signature on `LogixiaLogger` — remove `[K: string]: any`

---

## Current State Scorecard

| Dimension        | Score  | Notes                                                         |
| ---------------- | ------ | ------------------------------------------------------------- |
| Feature coverage | 8 / 10 | Ambitious, mostly shipped                                     |
| Type safety      | 4 / 10 | Several `any` holes and one crash-level bug                   |
| Test coverage    | 1 / 10 | 2 tests for a ~4 000-line codebase                            |
| Performance      | 5 / 10 | Fine for low volume, degrades above ~100 k logs               |
| Security         | 4 / 10 | Credentials in plain config, no path validation               |
| DX / ergonomics  | 7 / 10 | Good README, solid examples, but config duplication hurts     |
| npm SEO          | 3 / 10 | 0 keywords, generic description, no topics                    |
| Documentation    | 6 / 10 | README is long but JSDoc and architecture diagrams are absent |

---

## Recommended Sprint Order

### Sprint 1 — Stop the bleeding (1–2 days)

1. Fix `package.json` self-dep → `npm publish 1.0.4`
2. Fix `createLogger` private-method bug
3. Remove all `console.*` leaks from src
4. Fix silent `.catch` in NestJS service
5. Type `DatabaseTransport.connection`

### Sprint 2 — Build trust (3–5 days)

1. Write tests for core logger (all methods, level filtering, child logger)
2. Write tests for transports (console, file, DB mock)
3. Write tests for search (BasicSearchEngine full coverage)
4. Write tests for CLI commands
5. Set up GitHub Actions CI (Node 18 + 20 + 22 matrix)

### Sprint 3 — Fill the gaps (1 week)

1. Implement real file compression (zlib)
2. Replace static NestJS module state with instance scope
3. Add config schema validation (zod)
4. Add `LOGIXIA_*` env-var overrides
5. Add Prometheus `/metrics` exporter

### Sprint 4 — Grow (ongoing)

1. npm SEO: description, 40 keywords, repository/homepage fields
2. GitHub: description, 15 topics, banner image
3. LinkedIn post + Dev.to article
4. Show HN post

---

## File Map

```
todo/
├── 00-overview.md           ← you are here
├── 01-critical-bugs.md
├── 02-type-safety.md
├── 03-testing.md
├── 04-missing-features.md
├── 05-performance.md
├── 06-security.md
├── 07-dx-and-api.md
├── 08-seo-and-growth.md
└── 09-examples-and-docs.md
```
