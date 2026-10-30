# Security Policy

## Supported versions

| Version | Supported                                                                           |
| ------- | ----------------------------------------------------------------------------------- |
| 2.x     | Yes, the latest minor release                                                       |
| 1.x     | No. See the [migration guide](https://logixia.github.io/logixia/guide/migration-v2) |

Security fixes are released only for the latest minor of the current major.

## Reporting a vulnerability

Please do not open a public issue for security problems.

Report it privately through [GitHub private vulnerability reporting](https://github.com/Logixia/logixia/security/advisories/new). Include the version, a minimal reproduction, and the impact you expect.

You should get a reply within 3 working days. Once a fix is released, the advisory is published with credit to the reporter unless you ask otherwise.

## Release integrity

Releases are published from CI through npm trusted publishing with [npm provenance](https://docs.npmjs.com/generating-provenance-statements). The package has no install scripts.
