# logixia — TODO

> Format: `[ ]` = pending · `[x]` = done · `[~]` = in progress · `[!]` = blocked

---

## 🔴 Critical — Fix before next release

- [x] **[SEC] SQL Injection in Database Transport** (`src/transports/database.transport.ts`)
  - Table name is interpolated directly into queries: `` `INSERT INTO ${tableName}` ``
  - A user setting `config.table = "logs); DROP TABLE logs; --"` executes arbitrary SQL
  - Fix: validate table name against `/^[a-zA-Z_][a-zA-Z0-9_]*$/` before any query

- [x] **[SEC] DataDog API Key Exposed in URL Path** (`src/transports/datadog.transport.ts`)
  - Key is in the URL path: `'/v1/input/' + this.datadogConfig.apiKey`
  - If request fails and error is logged, the key leaks in the log entry
  - Fix: authenticate via `DD-API-KEY` header only, remove key from URL entirely

---

## 🟠 High — Fix this sprint

- [x] **[BUG] Database Batch Data Loss on Flush Failure** (`src/transports/database.transport.ts`)
  - `this.batch = []` is cleared BEFORE the DB write resolves
  - If the write throws, entries are permanently lost — recovery runs too late
  - Fix: copy entries → await write → clear original only on success

- [x] **[BUG] File Rotation Race Condition** (`src/transports/file.transport.ts`)
  - `shouldRotateNow()` and `rotate()` are not atomic
  - Two concurrent `write()` calls can both trigger rotation, corrupting file state
  - Fix: add `private isRotating = false` lock — skip if already rotating

- [x] **[BUG] Unhandled Promise in Batch Flush Timer** (`src/transports/file.transport.ts`)
  - Batch interval timer calls `this.flush()` as a fire-and-forget
  - On process exit before `.catch()` fires → unhandled rejection
  - Fix: track all in-flight flushes and drain them in `destroy()` / shutdown hook

- [x] **[BUG] Unbounded Namespace Pattern Cache (Memory Leak)** (`src/core/logitron-logger.ts`)
  - `_nsPatternCache` is a `Map` with no size cap or eviction policy
  - Apps using dynamic namespaces (per-request / per-tenant) will leak memory
  - Fix: cap at ~1000 entries, evict oldest on overflow (simple LRU)

---

## 🟡 Medium — Next cycle

- [x] **[CODE] `any` Cast on Transport Config** (`src/core/logitron-logger.ts`)
  - `(this.config as any).transports` — malformed transports cause silent, unclear errors
  - Fix: added `transports?: TransportConfig` to `LoggerConfig` type — cast removed

- [x] **[DX] Missing `"sideEffects": false`** (`package.json`)
  - No tree-shaking hint — bundlers pull in everything even for subpath-only imports
  - Fix: add `"sideEffects": false` to `package.json`

- [x] **[DX] No JSDoc on Public API Exports** (`src/index.ts` and core files)
  - `createLoggerService()`, `createLogger()`, transport classes have no JSDoc
  - IDE hover shows nothing — bad DX for consumers
  - Fix: added `@param`, `@returns`, `@example` JSDoc to all transport classes

- [x] **[DX] Result API not documented upfront in README** (`README.md`)
  - First code examples use try/catch — the whole point of logixia is structured logging
  - Fix: surfaced structured-data patterns, anti-patterns, and no-try/catch note in Quick Start

---

## 🔵 Low — Backlog

- [x] **[TEST] Jest Coverage Excludes `index.ts` Entry Points** (`jest.config.js`)
  - `'!src/**/index.ts'` in `collectCoverageFrom` — public re-export files never checked
  - Fix: removed exclusion — index.ts entry points now included in coverage

- [x] **[CI] No `npm ci` cache in workflows** (`.github/workflows/`)
  - `actions/setup-node` has no `cache: 'npm'` — installs are slow on every run
  - Fix: add `cache: 'npm'` to all workflow Node setup steps

- [ ] **[DEPS] Remove `inquirer` and `ora` from `dependencies`**
  - [x] Already removed from `package.json`
  - [ ] Run `npm install` locally to clean `node_modules`

---

## ✅ Done

- [x] Removed `inquirer` and `ora` from `dependencies` (were declared but never imported)
- [x] Fixed `lint` script glob — was `src/**/*.ts`, now `src/`
- [x] Added `test:ci`, `check`, `ci`, `validate` scripts to `package.json`
- [x] Updated `prepublishOnly` to run full `validate` (build + typecheck + lint + tests)
- [x] ROADMAP items #11–14 marked complete (NestJS, PII redaction, typed fields, OTel)
- [x] Fixed `OtelTransport` — `readonly id` → `readonly name`, `entry.payload` → `entry.data`
- [x] Fixed `LogixiaExceptionFilter` — removed `IBaseLogger` cast, added local `LogLike` interface
- [x] Fixed all ESLint issues in `pii-patterns.ts` (useless-escape, duplicates-in-character-class, regex-complexity)
- [x] Fixed `sonarjs/no-nested-conditional` in `logitron-logger.ts` and `logixia-exception-filter.ts`
- [x] Fixed `unicorn/consistent-destructuring` in `redact.utils.ts`
- [x] CI quality job: auto-fix formatting + lint, commit-back on PRs only
- [x] CI release job: `git fetch origin && git reset --hard origin/main` to fix "local branch behind remote"
- [x] Docs hero badge + footer version made dynamic (fetched from npm registry on load)
- [x] Docs JSON-LD `version` + `softwareVersion` updated dynamically
- [x] Docs GitHub stars shown dynamically in nav
