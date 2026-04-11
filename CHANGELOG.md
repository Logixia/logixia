# Changelog

All notable changes to **logixia** will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org).

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
