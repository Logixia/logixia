# Changelog

All notable changes to **logixia** will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org).

## [1.11.0](https://github.com/Logixia/logixia/compare/v1.10.3...v1.11.0) (2026-06-10)

### ✨ Features

* **runtime:** dynamic log-level reconfiguration without restart (R3+R4) ([ab5ad68](https://github.com/Logixia/logixia/commit/ab5ad6858e44c12e746919e655747b4de7ef4210)), closes [winston#1107](https://github.com/Logixia/winston/issues/1107) [206/#677](https://github.com/206/logixia/issues/677) [nestjs-pino#371](https://github.com/Logixia/nestjs-pino/issues/371)
* **sampling:** adaptive anomaly-driven sampling (R6) ([b80505b](https://github.com/Logixia/logixia/commit/b80505baff2a4b76d3b7bc68e10e982de5115c67))
* **transport:** OTLP Logs export — OpenTelemetry-native log emission (R2) ([6268ee7](https://github.com/Logixia/logixia/commit/6268ee738ccb0af775e4736298fd3a5716a1a6a8))
* **utils:** robust serialization beyond [Circular] — BigInt + $ref decycle (R9) ([9526ac7](https://github.com/Logixia/logixia/commit/9526ac7aba61df7683b0c525a2283310d6c3b686))
* **wide-events:** canonical log lines / wide events API (R1) ([86ad66a](https://github.com/Logixia/logixia/commit/86ad66a9daa21e599d2dc0c37825d6a3957c049a))

### 📚 Documentation

* document new roadmap features + flush-on-exit reliability guarantee (R5) ([0f4f372](https://github.com/Logixia/logixia/commit/0f4f3726b2654fb40130ed82577dbf420e837d7c)), closes [#1705](https://github.com/Logixia/logixia/issues/1705) [1889/#2054](https://github.com/1889/logixia/issues/2054)
* **research:** logger improvement research + prioritized roadmap ([8859212](https://github.com/Logixia/logixia/commit/88592126876cf0ba8d0451c534fb95eba4fe91e4)), closes [#1705](https://github.com/Logixia/logixia/issues/1705) [#206](https://github.com/Logixia/logixia/issues/206)

## [1.10.3](https://github.com/Logixia/logixia/compare/v1.10.2...v1.10.3) (2026-06-10)

### 🐛 Bug Fixes

* **browser:** drain whole batch and flush on destroy() to avoid log loss ([6bc9a85](https://github.com/Logixia/logixia/commit/6bc9a859c13d0e3b293e5f41c958555566ffefb5))
* **cli:** render falsy-but-real table cells (0, false) instead of blanks ([13f8454](https://github.com/Logixia/logixia/commit/13f8454b2a53a5d625dad86293823ef6621509a6))
* **formatters:** stop circular payloads from crashing JSON/text formatters ([69824eb](https://github.com/Logixia/logixia/commit/69824eb9eebe160afff33648fc6888f6f6ee112f))
* **internal-log:** read silence flag per call, not once at import ([e1d8a1c](https://github.com/Logixia/logixia/commit/e1d8a1cb38952a1e4b4be1aded6251b585acc25f))
* **middleware:** prevent duplicate request-completed logs from finish+close ([2f649f4](https://github.com/Logixia/logixia/commit/2f649f4d5ecbc90127c1054e265fb9f2aabab284))
* **nest:** @LogMethod preserves the sync/async contract of the wrapped method ([1418ebd](https://github.com/Logixia/logixia/commit/1418ebd437ee7932106ca0a9f472c17256536f86))
* **nest:** make formatMessage safe for circular and unserializable messages ([c5e0158](https://github.com/Logixia/logixia/commit/c5e0158e193ae91a5b77941c480ddd6c33ed3dfb))
* **nest:** tear down inner handler subscription in trace interceptors ([23ec529](https://github.com/Logixia/logixia/commit/23ec5295f30a014635db950ab9373d45b13c2d22))
* **otel,metrics:** harden OTel hot path and sanitize Prometheus names ([51cae52](https://github.com/Logixia/logixia/commit/51cae52ad1e1359fc3a2d458b1d94e99db5b9e89))
* **plugin:** isolate synchronous throws in onInit/onError/onShutdown hooks ([e361bdd](https://github.com/Logixia/logixia/commit/e361bdd5d20152e9ab59c19bffc8bc854ef16422))
* **redact:** actually commit the message-string redaction implementation ([55774a6](https://github.com/Logixia/logixia/commit/55774a6e9715fb6c7e6846442397d4b242dfe228))
* **redact:** redact pattern-matching secrets in the log message string ([0e8f915](https://github.com/Logixia/logixia/commit/0e8f9153dbb9a88b0eebbdbac8a0b4d5840934de))
* **sampling:** bound traceConsistent trace sets to prevent memory leak ([7b70f30](https://github.com/Logixia/logixia/commit/7b70f30ddf80db2c1e923fc29adc64938f064135))
* **search:** circular-safe searchable text and bound the engine buffer ([020a243](https://github.com/Logixia/logixia/commit/020a243e693393029edad298a02932952a136e33))
* **shutdown:** guard graceful-shutdown handler against concurrent signals ([85b1c56](https://github.com/Logixia/logixia/commit/85b1c56575033bce07745682d77f1499822e34f3))
* **trace:** harden NestJS trace middleware response + ip handling ([ada641b](https://github.com/Logixia/logixia/commit/ada641b61944e383dcef306189733820fe97eff6))
* **trace:** make createTraceMiddleware response-API agnostic ([f1e5625](https://github.com/Logixia/logixia/commit/f1e562581eb6c5a16967fbe102989a12a76bb28a))
* **transport:** add close() and full-batch drain to cloud transports ([d2917c2](https://github.com/Logixia/logixia/commit/d2917c20d94df26e8edfd1c092f3eb5320acc9be))
* **transport:** correct averageWriteTime metric and cover manager shutdown ([28049b2](https://github.com/Logixia/logixia/commit/28049b22ae7d83c7aace04f982b78c650fb1415b))
* **transport:** give WorkerTransport a close() and stop restart leaks ([91471c9](https://github.com/Logixia/logixia/commit/91471c93d12ffbdb60d4203a97b383af715e047f))
* **transport:** implement real gzip rotation and scope cleanup to own files ([f14a2e6](https://github.com/Logixia/logixia/commit/f14a2e614d67d9e3342a714becff8b6f97f9e02b))
* **transport:** serialize analytics flushes and guarantee drain on close ([ef3b66f](https://github.com/Logixia/logixia/commit/ef3b66fc967b86a7f300e6762046bc3cd8cb0199))
* **transport:** serialize database flushes and guarantee drain on close ([5f64995](https://github.com/Logixia/logixia/commit/5f64995f1b7ab2ea803198a39bcd2da8c7d43aeb))
* **utils:** stop safeToString returning undefined and harden error cycle guard ([748e199](https://github.com/Logixia/logixia/commit/748e1992bac7aae73a002bd3cb7ed49eb5bb40d1))

### ⚡ Performance

* **search:** make BasicLogIndexer.getIndexStats O(1) ([09efe2e](https://github.com/Logixia/logixia/commit/09efe2eac96360a518c25e9ee0309117ab01e3fb))

## [1.10.2](https://github.com/Logixia/logixia/compare/v1.10.1...v1.10.2) (2026-06-10)

### 🐛 Bug Fixes

* **console:** compact JSON, sanitize level for CWE-117, route warn to stderr ([c0108a9](https://github.com/Logixia/logixia/commit/c0108a942a242918e4050cc74ad523f5eb3b6181))
* **logger:** merge child/context data into log payload ([bc776d6](https://github.com/Logixia/logixia/commit/bc776d6580ba4db182dba981e29d99d4029d0daa))
* **plugins:** isolate throwing onLog and invoke onError on transport failure ([68be1bf](https://github.com/Logixia/logixia/commit/68be1bf1fa15609bde6cde9be7e92da4a9a80315))
* **redact:** apply autoDetect rules when no explicit paths or patterns set ([6df0c2a](https://github.com/Logixia/logixia/commit/6df0c2a3941a9893cae58be4131d6d72c8c61368))
* **redact:** make ** glob match zero segments so **.password redacts top-level keys ([e3ce30d](https://github.com/Logixia/logixia/commit/e3ce30dfe8fb8f8d2b72ee2f9934333dd6534555))
* **sampling:** always emit WARN regardless of global rate ([a7fb7f9](https://github.com/Logixia/logixia/commit/a7fb7f9a4cf54eb15dde59da14b063d378ff61d9))
* **shutdown:** register flush handler even when other signal listeners exist ([e30588d](https://github.com/Logixia/logixia/commit/e30588dea1cb1b473162ce6f100f20ecdf21b09c))
* **trace:** parse W3C traceId out of the traceparent header ([c74ae42](https://github.com/Logixia/logixia/commit/c74ae42b247efe0625bd656f4d169a717fe51e60))
* **transport:** prevent file log duplication from overlapping batch flushes ([a2fc846](https://github.com/Logixia/logixia/commit/a2fc84644b75b576299889390bffe5d2409846a9))

## [1.10.1](https://github.com/Logixia/logixia/compare/v1.10.0...v1.10.1) (2026-04-26)

### 📚 Documentation

* document transport filter predicate and graceful shutdown fix ([f8167ac](https://github.com/Logixia/logixia/commit/f8167acbc425f41c6d39950c1971121b82b28cb6))

## [1.10.0](https://github.com/Logixia/logixia/compare/v1.9.0...v1.10.0) (2026-04-26)

### ✨ Features

* add postinstall banner and funding field ([5544ce0](https://github.com/Logixia/logixia/commit/5544ce0f578f0884d1b9751bd2836ae3f0f94de5))

## [1.9.0](https://github.com/Logixia/logixia/compare/v1.8.6...v1.9.0) (2026-04-26)

### ✨ Features

* **transport:** add per-transport filter predicate ([10d8ce1](https://github.com/Logixia/logixia/commit/10d8ce1861a03c6d17453fd1a1a5535cc760d4b0))

## [1.8.6](https://github.com/Logixia/logixia/compare/v1.8.5...v1.8.6) (2026-04-26)

### 🐛 Bug Fixes

* **transport:** eliminate shutdown-phase log loss and noisy error spam ([7ec51a1](https://github.com/Logixia/logixia/commit/7ec51a1377aaf2ed802ac0a9e4c4144fe1a458a7))

## [1.8.5](https://github.com/Logixia/logixia/compare/v1.8.4...v1.8.5) (2026-04-17)

### 🐛 Bug Fixes

* **logger:** defend against non-string context and entry fields ([e639356](https://github.com/Logixia/logixia/commit/e639356ce75e6d56ee7f0f4975752460c0ad46c3))

## [1.8.4](https://github.com/Logixia/logixia/compare/v1.8.3...v1.8.4) (2026-04-11)

### 🐛 Bug Fixes

* **build:** stop bundling optional DB drivers + repair size-limit CI ([0336e00](https://github.com/Logixia/logixia/commit/0336e0057f5d78eaaf7c4ebe53ad9fd2a741a694))
* **ci:** disable husky hooks during semantic-release ([66f75a1](https://github.com/Logixia/logixia/commit/66f75a14e0805ed68232ca6971e2a88c960b839a))
* **ci:** stop husky leaking 'HUSKY=0 skip install' into npm pack stdout ([89efdb4](https://github.com/Logixia/logixia/commit/89efdb40e6b6f8680d84c7829468edbe9401b758))

### ♻️ Code Refactoring

* **cli:** migrate chalk → picocolors ([846f213](https://github.com/Logixia/logixia/commit/846f213e6797e77489c068b04f04b8e173fa373f))

## [1.8.3](https://github.com/Logixia/logixia/compare/v1.8.2...v1.8.3) (2026-04-11)

### ♻️ Code Refactoring

* **core:** production readiness pass — memory, ALS, logging, kafka metrics ([b9f2d68](https://github.com/Logixia/logixia/commit/b9f2d680c3d2947b5cb4e2a7da9049062721ae1e))

## [1.8.2](https://github.com/Logixia/logixia/compare/v1.8.1...v1.8.2) (2026-03-25)

### ♻️ Code Refactoring

* **trace:** remove requestId — use traceId as the single correlation ID ([9fc5cbf](https://github.com/Logixia/logixia/commit/9fc5cbf66357d0b5f76fa392830ee7a6dffb137d))

## [1.8.1](https://github.com/Logixia/logixia/compare/v1.8.0...v1.8.1) (2026-03-25)

### 🐛 Bug Fixes

* **exception-filter:** use global logger fallback in LogixiaExceptionFilter ([0e20c19](https://github.com/Logixia/logixia/commit/0e20c19f7e88e0f7cd348010446e0d4dd886bc79))

## [1.8.0](https://github.com/Logixia/logixia/compare/v1.7.2...v1.8.0) (2026-03-25)

### ✨ Features

* **log-method:** use global logger fallback so @LogMethod works without this.logger injection ([c4eddec](https://github.com/Logixia/logixia/commit/c4eddecedbf41afbdd10e74a6d0eb44761949fdb))

## [1.7.2](https://github.com/Logixia/logixia/compare/v1.7.1...v1.7.2) (2026-03-25)

### 🐛 Bug Fixes

* **log-method:** warn once when this.logger is missing instead of silently skipping ([38ff6b3](https://github.com/Logixia/logixia/commit/38ff6b38987f72e2cbc74cba8ea06b36d43edb2f))

## [1.7.1](https://github.com/Logixia/logixia/compare/v1.7.0...v1.7.1) (2026-03-25)

### ♻️ Code Refactoring

* **trace:** replace scattered trace fns with TraceContext singleton class ([c8e6456](https://github.com/Logixia/logixia/commit/c8e64569669c2f1a277815fb067a58467f1d7279))

## [1.7.0](https://github.com/Logixia/logixia/compare/v1.6.8...v1.7.0) (2026-03-25)

### ✨ Features

* **trace:** export TRACE_CONTEXT_KEY constant and logger.traceContextKey getter ([4043c96](https://github.com/Logixia/logixia/commit/4043c962cdad0d4a8771ff60e2499ffd6e17c654))

## [1.6.8](https://github.com/Logixia/logixia/compare/v1.6.7...v1.6.8) (2026-03-25)

### 🐛 Bug Fixes

* **trace-middleware:** deep-merge extractor config instead of shallow-spread ([f69fd91](https://github.com/Logixia/logixia/commit/f69fd9141466b1707e71231c9f532b2e78721943))

## [1.6.7](https://github.com/Logixia/logixia/compare/v1.6.6...v1.6.7) (2026-03-24)

### 🐛 Bug Fixes

* **nestjs-extras:** widen @LogMethod level type to accept custom log levels ([9c4ca61](https://github.com/Logixia/logixia/commit/9c4ca611ddcf03cfe129ffb14dea515c3d8c2069))

## [1.6.6](https://github.com/Logixia/logixia/compare/v1.6.5...v1.6.6) (2026-03-24)

### 🐛 Bug Fixes

* **trace-middleware:** add @Optional() to TraceMiddleware constructor ([3778a79](https://github.com/Logixia/logixia/commit/3778a79b334368b698d12b7e2c2449db6abf2992))

## [1.6.5](https://github.com/Logixia/logixia/compare/v1.6.4...v1.6.5) (2026-03-24)

### 🐛 Bug Fixes

* **context:** update JSDoc for randomShortId function ([1174278](https://github.com/Logixia/logixia/commit/1174278bd106b9c752a81133aa797d761bdff5d8))

## [1.6.4](https://github.com/Logixia/logixia/compare/v1.6.3...v1.6.4) (2026-03-24)

### 🐛 Bug Fixes

* align @nestjs/common version — peerDep ^10||^11, devDep ^11 ([261663d](https://github.com/Logixia/logixia/commit/261663d421618c1e53fbbecf638afc82f99e0be1))
* **context:** use node:crypto randomUUID instead of global crypto ([5bdbd3d](https://github.com/Logixia/logixia/commit/5bdbd3d0146e1c837fdcd0944a34facf9fdde314))
* correct PostgreSQL INSERT placeholders and add NestJS example app ([312bbfa](https://github.com/Logixia/logixia/commit/312bbfa5e84025407b41eca3b7a82b5bf07053fe))
* **peer-deps:** broaden peerDependencies to support NestJS 11 and reflect-metadata 0.2.x ([657dfaa](https://github.com/Logixia/logixia/commit/657dfaa0b017131d2bc4f1441e41d97ba2d3f5d4))
* refactor LogMethod binding and pass structured meta to ExceptionFilter ([1ef8da2](https://github.com/Logixia/logixia/commit/1ef8da2ac4995a8c687a5dda233b966007b14e32))

### 📚 Documentation

* **examples:** add transports-deep-dive.ts with verified real output ([d4df576](https://github.com/Logixia/logixia/commit/d4df576baa77496c706010438ed3b8aac8d7422b))
* update README with real error shape, interceptor usage, and example app ([df6925c](https://github.com/Logixia/logixia/commit/df6925c798b699f43f81adc35668431bec01ab0f))

## [1.6.3](https://github.com/Logixia/logixia/compare/v1.6.2...v1.6.3) (2026-03-24)

### 🐛 Bug Fixes

* pass levelOptions.colors to ConsoleTransport so custom levels are colored ([6138fe6](https://github.com/Logixia/logixia/commit/6138fe652fdb3ce2fc20e01c150fae02450b9458))

## [1.6.2](https://github.com/Logixia/logixia/compare/v1.6.1...v1.6.2) (2026-03-24)

### 🐛 Bug Fixes

* colorize timestamp/appName/traceId/context fields and fix file dirname ([f7e4fe4](https://github.com/Logixia/logixia/commit/f7e4fe461b83e6e14bec99854ea3045cc264ebb8))

## [1.6.1](https://github.com/Logixia/logixia/compare/v1.6.0...v1.6.1) (2026-03-24)

### 🐛 Bug Fixes

* add missing bright/grey color variants to ANSI color map ([21de116](https://github.com/Logixia/logixia/commit/21de11662ef687be983c3b06c9e7f4e270d7bb7d))

## [1.6.0](https://github.com/Logixia/logixia/compare/v1.5.0...v1.6.0) (2026-03-24)

### ✨ Features

* custom level proxy methods, auto-palette colors, and IntelliSense ([245bf13](https://github.com/Logixia/logixia/commit/245bf13d265390eaee4b5696268e9b17bbe26874))

## [1.5.0](https://github.com/Logixia/logixia/compare/v1.4.0...v1.5.0) (2026-03-18)

### ✨ Features

* add typed LogixiaException system and enhance NestJS compat ([5ce1938](https://github.com/Logixia/logixia/commit/5ce1938f6bcba1e575bf743ffe89b04ffaf853fe))

## [1.4.0](https://github.com/Logixia/logixia/compare/v1.3.1...v1.4.0) (2026-03-16)

### ✨ Features

* add CLI explore command for TUI log browsing ([5fa1475](https://github.com/Logixia/logixia/commit/5fa1475cf920b3fa1c70faf0057f4a8cb1444053))
* add cloud transports, correlation tracking, and browser support ([1566e5a](https://github.com/Logixia/logixia/commit/1566e5a0c9b4e2124fb9cab08c3935b2420cc5c8))
* implement plugin system and Prometheus metrics support ([084e6c3](https://github.com/Logixia/logixia/commit/084e6c3481a9db629b370c69da131bc9fb222d2c))

### 📚 Documentation

* update README with CLI subcommands overview and explore options ([1859d94](https://github.com/Logixia/logixia/commit/1859d941b05b777b329fc14f69cf1b534422842e))
* update README with cloud transports, correlation tracking, and CLI query details ([9640fa3](https://github.com/Logixia/logixia/commit/9640fa3bc64f7769e41eb878d2ea5674a8045060))

## [1.3.1](https://github.com/Logixia/logixia/compare/v1.3.0...v1.3.1) (2026-03-14)

### 📚 Documentation

* add dynamic metadata fetch and refactor package scripts ([dcb706f](https://github.com/Logixia/logixia/commit/dcb706f097d6ac2a1b5d745e2f172a5e7a5d57f7))

## [1.3.0](https://github.com/Logixia/logixia/compare/v1.2.1...v1.3.0) (2026-03-14)

### ✨ Features

* implement decorators, exception filters, sampling, and integrations ([46cd66e](https://github.com/Logixia/logixia/commit/46cd66eb899e049f10ee666bb406b619b1fa680d))

### 📚 Documentation

* mark v1.2 features as complete in roadmap ([2a6b5c0](https://github.com/Logixia/logixia/commit/2a6b5c06354f1120ad1ca1f4489bc3bed4accaf8))

## [1.2.1](https://github.com/Logixia/logixia/compare/v1.2.0...v1.2.1) (2026-03-14)

### 🐛 Bug Fixes

* correct package exports for CJS/ESM interop and update CI artifact verification ([28c2a36](https://github.com/Logixia/logixia/commit/28c2a3646a89326235305dbd5922cdb179ec3dde))

## [1.2.0](https://github.com/Logixia/logixia/compare/v1.1.5...v1.2.0) (2026-03-14)

### ✨ Features

* expose sub-path exports for nest, transports, and search modules ([43e0f48](https://github.com/Logixia/logixia/commit/43e0f487f101943c0072eb3480efc0ce4c76231d))

### 📚 Documentation

* update URLs and branding references across README and docs ([d44561e](https://github.com/Logixia/logixia/commit/d44561e78d61968039881ef4a34ce281c71dd1e7))

## [1.1.5](https://github.com/Logixia/logixia/compare/v1.1.4...v1.1.5) (2026-03-14)

### 📚 Documentation

* update landing page content and styling ([881304a](https://github.com/Logixia/logixia/commit/881304a9c129ff062d3466b835af2c6e2eaaa47b))

## [1.1.4](https://github.com/Logixia/logixia/compare/v1.1.3...v1.1.4) (2026-03-14)

### 📚 Documentation

* add Timer API, CLI tool, and detailed configuration reference ([b7a1fc8](https://github.com/Logixia/logixia/commit/b7a1fc84108b01fe146e93291ba19d9408233306))

## [1.1.3](https://github.com/Logixia/logixia/compare/v1.1.2...v1.1.3) (2026-03-14)

### 📚 Documentation

* add github pages deployment workflow and docs entry point ([f3639a2](https://github.com/Logixia/logixia/commit/f3639a28137469c576832bec43160fe99e023726))

## [1.1.2](https://github.com/Logixia/logixia/compare/v1.1.1...v1.1.2) (2026-03-14)

### 📚 Documentation

- update README with comprehensive features and examples ([93ee9a9](https://github.com/Logixia/logixia/commit/93ee9a9aa9aa2b9d597ff89f1eec667b33734f8b))

## [1.1.1](https://github.com/Logixia/logixia/compare/v1.1.0...v1.1.1) (2026-03-14)

### ♻️ Code Refactoring

- **core:** enhance LogitronLogger and transports, update benchmarks ([e22b113](https://github.com/Logixia/logixia/commit/e22b1134a1af2c6e71c45a613abdafbf3cf49104))

## [1.1.0](https://github.com/Logixia/logixia/compare/v1.0.4...v1.1.0) (2026-03-14)

### ✨ Features

- add benchmark run script ([37809af](https://github.com/Logixia/logixia/commit/37809af2c5725285f62063c36b7fe5edfad4d1d9))
- add graceful shutdown, log redaction, error serialization, and adaptive log levels (v1.1) ([f538710](https://github.com/Logixia/logixia/commit/f538710cf8c9c4daddf76175e1405e7c687aac16))

### 🐛 Bug Fixes

- **ci:** install optional deps for rolldown binding ([0979fb2](https://github.com/Logixia/logixia/commit/0979fb2ce8eb6b01f8198933d5ed2adc1498bb19))
- **ci:** remove package-lock.json to fix rolldown binding ([5995347](https://github.com/Logixia/logixia/commit/599534750e23f0374d250d4465dd7b0d062af380))
