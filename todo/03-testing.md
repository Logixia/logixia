# 03 — Testing Plan

> Current state: **2 tests** covering a ~4 000-line codebase.
> That is roughly **< 5 % functional coverage**.
> This file is the complete test plan needed to reach 80 %+ coverage.

---

## Current Test Inventory

| File                                 | Tests | What they cover                                   |
| ------------------------------------ | ----- | ------------------------------------------------- |
| `test/analyze.test.ts`               | 2     | `analyzeFileContents()` time filter + empty input |
| `src/cli/__tests__/analyze.test.ts`  | ~3    | CLI analyze command                               |
| `src/cli/__tests__/commands.test.ts` | ~3    | CLI command parsing                               |

**Total: ~8 tests — essentially nothing for a production logging library.**

---

## Test Infrastructure

### Current setup

- Jest 29 + ts-jest
- `jest.config.js` present

### Recommended additions

```js
// jest.config.js — add coverage thresholds
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/test'],
  testMatch: ['**/__tests__/**/*.test.ts', '**/test/**/*.test.ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/cli/**', // CLI tested separately
    '!src/**/*.d.ts',
  ],
  coverageThresholds: {
    global: {
      branches: 70,
      functions: 80,
      lines: 80,
      statements: 80,
    },
  },
  // Mock optional peer deps
  moduleNameMapper: {
    '^mongodb$': '<rootDir>/test/__mocks__/mongodb.ts',
    '^pg$': '<rootDir>/test/__mocks__/pg.ts',
    '^mysql2/promise$': '<rootDir>/test/__mocks__/mysql2.ts',
    '^sqlite3$': '<rootDir>/test/__mocks__/sqlite3.ts',
    '^@nestjs/(.*)$': '<rootDir>/test/__mocks__/nestjs.ts',
  },
};
```

### Mock files to create

**`test/__mocks__/mongodb.ts`**

```typescript
export const MongoClient = jest.fn().mockImplementation(() => ({
  connect: jest.fn().mockResolvedValue(undefined),
  db: jest.fn().mockReturnValue({
    collection: jest.fn().mockReturnValue({
      insertMany: jest.fn().mockResolvedValue({ insertedCount: 1 }),
    }),
  }),
  close: jest.fn().mockResolvedValue(undefined),
}));
```

Create similar mocks for `pg`, `mysql2`, `sqlite3`, and NestJS decorators.

---

## Test Suites to Write

### SUITE 1: Core Logger

**File:** `src/core/__tests__/logixia-logger.test.ts`

```
describe('LogixiaLogger', () => {
  describe('constructor & factory', () => {
    ✅ createLogger() returns LogixiaLogger instance
    ✅ createLogger() with no config uses DEFAULT_CONFIG
    ✅ createLogger() with custom appName uses it in log entries
    ✅ createLogger() creates dynamic methods for each customLevel key
    ✅ dynamic custom level method calls logLevel() with correct level name
    ✅ createLogger() with duplicate level name throws or warns
  });

  describe('standard log methods', () => {
    ✅ error(message) calls transport with level=error
    ✅ error(Error instance) serializes the error object
    ✅ warn(message) calls transport with level=warn
    ✅ info(message) calls transport with level=info
    ✅ debug(message) calls transport with level=debug
    ✅ trace(message) calls transport with level=trace
    ✅ verbose(message) calls transport with level=verbose
    ✅ all methods include payload when data is passed
    ✅ all methods respect the current log level (filtered out below min)
    ✅ log entries include a timestamp
    ✅ log entries include appName from config
  });

  describe('level filtering', () => {
    ✅ setLevel('warn') suppresses debug and info
    ✅ setLevel('warn') allows warn and error
    ✅ setLevel('error') suppresses all below error
    ✅ setLevel('trace') passes all levels
    ✅ getLevel() returns current level
  });

  describe('child loggers', () => {
    ✅ child() returns a new LogixiaLogger instance
    ✅ child logger inherits parent config
    ✅ child logger has its own context
    ✅ child logger does NOT affect parent context
    ✅ child logger entries include child context fields
  });

  describe('timing utilities', () => {
    ✅ time(label) starts a timer
    ✅ timeEnd(label) logs duration since time(label)
    ✅ timeEnd(unknown label) logs a warning
    ✅ timeAsync(label, fn) wraps the function and logs duration
    ✅ timeAsync(label, fn) resolves with fn's return value
    ✅ timeAsync(label, fn) still logs duration when fn rejects
  });

  describe('context management', () => {
    ✅ setContext(ctx) / getContext() round-trips
    ✅ context fields appear in log entries
  });

  describe('field management', () => {
    ✅ disableField(fieldName) excludes that field from output
    ✅ enableField(fieldName) re-enables it
    ✅ isFieldEnabled() returns correct boolean
    ✅ resetFieldState() restores all fields
    ✅ getFieldState() returns map of enabled fields
  });

  describe('flush & close', () => {
    ✅ flush() calls flush() on all transports
    ✅ close() calls close() on all transports
    ✅ close() resolves even when a transport.close() rejects
  });

  describe('healthCheck', () => {
    ✅ returns { healthy: true } when all transports report healthy
    ✅ returns { healthy: false, details } when a transport is unhealthy
  });
});
```

---

### SUITE 2: Transport — Console

**File:** `src/transports/__tests__/console.transport.test.ts`

```
describe('ConsoleTransport', () => {
  ✅ write() calls console.error for error level
  ✅ write() calls console.warn for warn level
  ✅ write() calls console.log for info/debug/trace
  ✅ write() formats output as JSON when format=json
  ✅ write() formats output as text when format=text
  ✅ write() includes timestamp when showTimestamp=true
  ✅ write() omits timestamp when showTimestamp=false
  ✅ write() includes appName when showAppName=true
  ✅ level filtering — write() is no-op when entry level < transport level
  ✅ flush() resolves immediately (no-op for console)
  ✅ close() resolves immediately (no-op for console)
});
```

---

### SUITE 3: Transport — File

**File:** `src/transports/__tests__/file.transport.test.ts`

```
describe('FileTransport', () => {
  beforeEach(() => mock the filesystem (use memfs or jest.mock('fs'))

  ✅ write() appends to the target file
  ✅ write() batches entries up to batchSize
  ✅ batch flushes after batchInterval ms
  ✅ batch flushes when batchSize is reached
  ✅ rotation: rotateFile() renames current file with timestamp suffix
  ✅ rotation: new file is created after rotation
  ✅ rotation: maxFiles limit removes oldest files
  ✅ format=json writes valid JSON lines
  ✅ format=csv writes valid CSV with header
  ✅ format=text writes human-readable lines
  ✅ flush() writes pending batch immediately
  ✅ close() flushes then ends write stream (no process hang)
  ✅ close() clears the flush interval
});
```

---

### SUITE 4: Transport — Database (mocked)

**File:** `src/transports/__tests__/database.transport.test.ts`

```
describe('DatabaseTransport — MongoDB', () => {
  ✅ connect() calls MongoClient.connect()
  ✅ write() queues entries in batch
  ✅ batch insert is called when batchSize reached
  ✅ batch insert is called on flush()
  ✅ failed insert re-queues items (retry behaviour)
  ✅ close() flushes batch then closes MongoClient
});

describe('DatabaseTransport — PostgreSQL', () => {
  ✅ connect() creates a pg.Pool
  ✅ writeBatch() calls pool.query() with correct INSERT
  ✅ handles pg connection error gracefully
});

// Similar for MySQL, SQLite
```

---

### SUITE 5: Search — BasicSearchEngine

**File:** `src/search/__tests__/basic-search-engine.test.ts`

```
describe('BasicSearchEngine', () => {
  describe('indexing', () => {
    ✅ indexLog() adds entry to index
    ✅ index respects maxSize — evicts oldest when full
    ✅ clear() empties the index
    ✅ getStats() returns correct count and index size
  });

  describe('search', () => {
    ✅ search('') returns all entries up to limit
    ✅ search('error') returns entries containing 'error' in message
    ✅ filter by level — only returns entries at specified levels
    ✅ filter by timeRange — only returns entries in window
    ✅ filter by traceId — only returns entries with matching trace
    ✅ filter by service — only returns entries from that service
    ✅ pagination: skip + limit work correctly
    ✅ sort: ascending timestamp order
    ✅ sort: descending timestamp order
    ✅ context enrichment: returns N lines before/after match
    ✅ highlighting: matched terms are wrapped in highlight markers
    ✅ empty result set returns SearchResult[] = []
  });

  describe('suggestions', () => {
    ✅ getSuggestions('er') returns level:error, level:warn suggestions
    ✅ suggestion cache is used on repeated identical queries
    ✅ search history is recorded
    ✅ getSuggestions includes previous search terms from history
  });

  describe('presets', () => {
    ✅ savePreset() stores a preset with name+filters
    ✅ getPresets() returns all saved presets
    ✅ runPreset(name) executes filters from preset
    ✅ deletePreset(name) removes the preset
  });

  describe('correlation', () => {
    ✅ findRelated(logId) returns logs with same traceId
    ✅ getCorrelatedLogs(traceId) returns sorted timeline
  });
});
```

---

### SUITE 6: Search — NLPSearchEngine

**File:** `src/search/__tests__/nlp-search-engine.test.ts`

```
describe('NLPSearchEngine', () => {
  ✅ parseQuery('show errors from last hour') extracts level=error + time filter
  ✅ parseQuery('find requests for user 42') extracts userId=42
  ✅ parseQuery('trace abc123') extracts traceId=abc123
  ✅ parseQuery('payment failures today') extracts intent=find_errors + service hint
  ✅ confidence score is between 0 and 1
  ✅ unknown query returns low confidence + empty filters
  ✅ search() delegates to BasicSearchEngine with parsed filters applied
});
```

---

### SUITE 7: Utils

**File:** `src/utils/__tests__/trace.utils.test.ts`

```
describe('Trace Utilities', () => {
  ✅ generateTraceId() returns a string matching UUID v4 format
  ✅ generateTraceId() returns different values on each call
  ✅ getCurrentTraceId() returns undefined when not in trace context
  ✅ setTraceId(id) + getCurrentTraceId() returns same id in same async context
  ✅ runWithTraceId(id, fn) sets trace during fn execution
  ✅ trace id does not leak across unrelated async chains
  ✅ extractTraceId() reads from request header (default 'x-trace-id')
  ✅ extractTraceId() reads from custom header when configured
  ✅ extractTraceId() returns undefined when header absent
});
```

**File:** `src/utils/__tests__/error.utils.test.ts`

```
describe('Error Utilities', () => {
  ✅ serializeError(new Error('msg')) returns { name, message, stack }
  ✅ serializeError includes cause when Error.cause is set
  ✅ serializeError respects includeStack=false option
  ✅ serializeError handles cyclic error objects
  ✅ serializeError(non-error) converts to Error first via normalizeError()
  ✅ isError(new Error()) returns true
  ✅ isError({}) returns false
  ✅ isError(null) returns false
  ✅ normalizeError(string) wraps in Error with that message
  ✅ normalizeError(Error) returns same instance
});
```

---

### SUITE 8: NestJS Integration

**File:** `src/core/__tests__/logitron-nestjs.service.test.ts`

```
describe('LogixiaLoggerService', () => {
  ✅ create() returns LogixiaLoggerService instance
  ✅ log(message, context) delegates to logger.info
  ✅ error(message, trace, context) delegates to logger.error with stack
  ✅ warn(message, context) delegates to logger.warn
  ✅ debug(message, context) delegates to logger.debug
  ✅ verbose(message, context) delegates to logger.verbose
  ✅ transport failure is not re-thrown (graceful degradation)
  ✅ transport failure emits 'transport:error' event
  ✅ getCurrentTraceId() is included in log entry when available
});
```

---

### SUITE 9: CLI Commands

**File:** `src/cli/__tests__/all-commands.test.ts`

```
describe('CLI — search command', () => {
  ✅ --query flag filters by text
  ✅ --level flag filters by level
  ✅ --format=json outputs valid JSON
  ✅ --format=table outputs tabular text
  ✅ --context=2 returns 2 surrounding lines
});

describe('CLI — stats command', () => {
  ✅ groups by level by default
  ✅ --group-by=service groups by service
  ✅ --format=json outputs valid JSON
});

describe('CLI — export command', () => {
  ✅ --format=csv outputs valid CSV with header row
  ✅ --format=json outputs valid JSON array
  ✅ --fields=timestamp,level limits columns in output
  ✅ writes to file when --output is specified
});

describe('CLI — tail command', () => {
  ✅ --last N shows last N lines
  ✅ --level filters output
  ✅ exits cleanly when not in follow mode
});
```

---

## CI Configuration

**`.github/workflows/ci.yml`** — create or update:

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        node-version: ['18', '20', '22']

    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: npm
      - run: npm ci
      - run: npm run build
      - run: npm test -- --coverage
      - uses: codecov/codecov-action@v4 # optional but great for badges
```

---

## Coverage Target by Release

| Release      | Target | Scope                  |
| ------------ | ------ | ---------------------- |
| v1.0.4 (now) | 10 %   | Fix critical bugs only |
| v1.1.0       | 40 %   | Suites 1 + 2 + 7       |
| v1.2.0       | 65 %   | Suites 3 + 4 + 8       |
| v1.3.0       | 80 %   | Suites 5 + 6 + 9       |
