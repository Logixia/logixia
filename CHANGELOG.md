# Changelog

All notable changes to **logixia** will be documented in this file.
This project adheres to [Semantic Versioning](https://semver.org).

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
