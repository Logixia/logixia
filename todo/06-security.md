# 06 — Security

> A logging library touches credentials, file paths, and HTTP headers.
> Each section below is an independently exploitable attack surface.

---

## SEC-01 🟠 Database credentials stored in plaintext config

**Affected file:** `src/transports/database.transport.ts`

### The problem
```typescript
createLogger({
  transports: [{
    type: 'database',
    url: 'mongodb://admin:s3cr3tp@ssword@db.internal:27017/logs',
    // ↑ Password visible in source, process memory, and stack traces
  }]
});
```

Stack traces that include `config` will leak the connection string.
Log entries that record the config will persist the password in the very log files
you're writing to.

### Fix

**Step 1 — Support environment variable references in config**
```typescript
interface DatabaseTransportConfig {
  url?: string;
  urlEnvVar?: string;   // NEW — e.g. 'LOGIXIA_DB_URL'
}

// Resolved at connection time, not stored on the object
function resolveUrl(config: DatabaseTransportConfig): string {
  if (config.urlEnvVar) {
    const url = process.env[config.urlEnvVar];
    if (!url) throw new Error(`Environment variable ${config.urlEnvVar} is not set`);
    return url;
  }
  if (config.url) return config.url;
  throw new Error('Database transport requires url or urlEnvVar');
}
```

**Step 2 — Never include `url` in serialised error messages**
```typescript
// When logging a connection error, redact the URL
internalError(
  `Database transport connection failed (URL redacted)`,
  new Error(err.message),  // do NOT include the original err which may have URL in stack
);
```

**Step 3 — Recommend `.env` in the README example**
```typescript
// Recommended pattern
createLogger({
  transports: [{
    type: 'database',
    urlEnvVar: 'LOGIXIA_DB_URL',  // ← env var, not inline string
  }]
});
```

---

## SEC-02 🟠 File transport path traversal vulnerability

**File:** `src/transports/file.transport.ts`

### The problem
```typescript
// Config accepts any path
createLogger({
  transports: [{
    type: 'file',
    filename: '../../../../etc/cron.d/evil',  // path traversal
  }]
});
```

If a web app lets users configure logixia (e.g. a SaaS with per-tenant logging),
a malicious user can write to arbitrary paths.

### Fix — validate and normalise the file path

```typescript
import { resolve, normalize, isAbsolute } from 'node:path';

function validateFilePath(input: string, allowedBasePath?: string): string {
  const normalised = normalize(resolve(input));

  // If an allowedBasePath is configured, enforce it
  if (allowedBasePath) {
    const base = resolve(allowedBasePath);
    if (!normalised.startsWith(base + '/') && normalised !== base) {
      throw new Error(
        `File transport path "${input}" is outside allowed directory "${allowedBasePath}"`,
      );
    }
  }

  // Reject suspicious patterns even without a base path
  if (normalised.includes('\0')) {
    throw new Error('File path contains null byte');
  }

  return normalised;
}
```

Add `allowedBasePath` to `FileTransportConfig`:
```typescript
interface FileTransportConfig {
  filename: string;
  allowedBasePath?: string;  // e.g. '/var/log/myapp'
}
```

---

## SEC-03 🟡 CLI commands — no input validation on `--query`, `--level`, `--output`

**Files:** `src/cli/commands/*.ts`

### The problem

```bash
logixia search --query '$(rm -rf /)'      # shell injection in some contexts
logixia export --output '/etc/passwd'     # write to system files
logixia search --level 'UNION SELECT 1;' # log injection (if writing to DB)
```

### Fix

**Validate level against the known enum:**
```typescript
const VALID_LEVELS = ['error', 'warn', 'info', 'debug', 'trace', 'verbose'] as const;

function validateLevel(value: string): LogLevelString {
  if (!VALID_LEVELS.includes(value as LogLevelString)) {
    throw new Error(`Invalid level: "${value}". Must be one of: ${VALID_LEVELS.join(', ')}`);
  }
  return value as LogLevelString;
}
```

**Validate output path:**
```typescript
function validateOutputPath(value: string): string {
  // Disallow absolute system paths
  const normalised = resolve(value);
  const cwd = process.cwd();
  if (!normalised.startsWith(cwd)) {
    console.error(`Output path must be within the current directory`);
    process.exit(1);
  }
  return normalised;
}
```

**Sanitise query string before passing to search engine:**
```typescript
function sanitizeQuery(q: string): string {
  // Remove null bytes and control characters
  return q.replace(/[\x00-\x1F\x7F]/g, '').trim().slice(0, 1000);
}
```

---

## SEC-04 🟡 Analytics transport API keys stored in config object

**Files:** `src/transports/mixpanel.transport.ts`,
`src/transports/datadog.transport.ts`,
`src/transports/segment.transport.ts`

Same issue as SEC-01 but for analytics keys:

```typescript
// Current — key visible in source and stack traces
createLogger({
  transports: [{
    type: 'mixpanel',
    token: 'abc123secret',
  }]
});
```

### Fix — add `tokenEnvVar`, `apiKeyEnvVar` alongside direct key fields

```typescript
interface MixpanelTransportConfig {
  token?: string;
  tokenEnvVar?: string;  // 'MIXPANEL_TOKEN'
}

interface DatadogTransportConfig {
  apiKey?: string;
  apiKeyEnvVar?: string;  // 'DD_API_KEY'
}
```

---

## SEC-05 🟡 `serializeError` — circular reference protection is incomplete

**File:** `src/utils/error.utils.ts`

A cyclic error object (`error.cause = error`) should not crash the serializer.
The current implementation has a `maxDepth` limit but no explicit cycle detection.

### Fix — add a `WeakSet` of visited objects

```typescript
function serializeError(
  error: unknown,
  options: SerializeOptions = {},
  visited = new WeakSet(),
): SerializedError {
  if (error instanceof Error) {
    if (visited.has(error)) {
      return { name: 'CircularReference', message: '[Circular]' };
    }
    visited.add(error);
    return {
      name:    error.name,
      message: error.message,
      stack:   options.includeStack !== false ? error.stack : undefined,
      cause:   error.cause
                 ? serializeError(error.cause, options, visited)
                 : undefined,
    };
  }
  // ...
}
```

---

## SEC-06 🟢 Log injection — user-supplied strings written verbatim to log files

If a user sends a request with `Content-Type: application/json` and the body
contains newlines or ANSI escape codes, those are written directly to log files:

```
User-Agent: Mozilla/5.0\n[FAKE ERROR] database credentials: admin:password
```

This can poison structured log parsing and confuse log analysis tools.

### Fix — sanitise message strings before writing

```typescript
function sanitizeMessage(message: string): string {
  // Remove ANSI escape codes
  const stripped = message.replace(/\x1B\[[0-9;]*[mGKHF]/g, '');
  // Escape newlines in single-line log formats
  return stripped.replace(/\r?\n/g, '\\n').replace(/\r/g, '\\r');
}
```

Apply this in `TextFormatter.format()` for the `message` field.
JSON format is naturally safe because newlines are JSON-escaped automatically.

---

## SEC-07 🟢 Dependency audit — check for known vulnerabilities

```bash
npm audit
```

Key concerns:
- `chalk ^5.x` — check for prototype pollution (none known, but good habit)
- `commander ^11.x` — argument injection edge cases
- `inquirer ^9.x` — any known input handling issues

Set up automated dependency updates:

**`.github/dependabot.yml`**
```yaml
version: 2
updates:
  - package-ecosystem: npm
    directory: /
    schedule:
      interval: weekly
    open-pull-requests-limit: 10
```

---

## Security Checklist for each Release

- [ ] `npm audit` shows 0 high/critical vulnerabilities
- [ ] No credentials appear in any example file or documentation
- [ ] File paths are validated before opening
- [ ] CLI inputs are validated against allow-lists
- [ ] Error messages do not include database URLs or API keys
