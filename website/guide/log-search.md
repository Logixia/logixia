---
title: Log search and analysis
description: 'Search, correlate and analyze logs in memory with logixia/search SearchManager: filters, natural language queries, trace correlation, patterns and export.'
order: 18
---

# Log search and analysis

`logixia/search` provides `SearchManager`, an in-memory index and search engine for log entries. Load entries into it, then query by text, filters, natural-language phrases or trace ID, and look for repeated patterns and anomalies.

It works on arrays of `LogEntry` objects that you already have, for example parsed from a log file or read from a database. It does not read files or connect to a log store by itself, and the index lives in the process's memory.

```ts
import { SearchManager } from 'logixia/search';
import type { LogEntry } from 'logixia';

const logs: LogEntry[] = [
  {
    timestamp: new Date().toISOString(),
    level: 'error',
    appName: 'payments',
    message: 'payment failed: card declined',
    traceId: 'trace-1',
    payload: { userId: 'u_9', amount: 49.9 },
  },
  {
    timestamp: new Date().toISOString(),
    level: 'info',
    appName: 'payments',
    message: 'retrying charge',
    traceId: 'trace-1',
  },
];

const searcher = new SearchManager();
await searcher.indexLogs(logs);

const results = await searcher.search(
  'payment failed',
  { levels: ['error'] },
  { limit: 50, sortBy: 'timestamp', sortOrder: 'desc' }
);

for (const result of results) {
  console.log(result.score, result.log.message);
}
```

## Configuration

`new SearchManager(config?)` accepts:

| Option                     | Default   | Description                                        |
| -------------------------- | --------- | -------------------------------------------------- |
| `enableNLP`                | `true`    | Use the natural-language engine for queries.       |
| `enablePatternRecognition` | `true`    | Enable `detectPatterns()` and `detectAnomalies()`. |
| `enableCorrelation`        | `true`    | Enable related-log and error-cascade analysis.     |
| `maxIndexSize`             | `1000000` | Maximum number of indexed entries.                 |
| `autoOptimize`             | `true`    | Let the indexer optimize itself.                   |

Methods that need a disabled feature throw (`'Pattern recognition not enabled'`, `'Correlation engine not enabled'`).

## Indexing

| Method                | Description                                                      |
| --------------------- | ---------------------------------------------------------------- |
| `indexLogs(logs)`     | Index an array of entries.                                       |
| `indexLog(log)`       | Index one entry.                                                 |
| `removeOldLogs(date)` | Remove entries older than `date`; returns how many were removed. |
| `clearIndex()`        | Remove everything.                                               |
| `optimizeIndex()`     | Optimize the index.                                              |
| `getIndexStats()`     | `{ totalDocuments, indexSize, lastOptimized? }`.                 |

## Searching

`search(query, filters?, options?)` returns `SearchResult[]`, each with the `log`, a relevance `score` and optional `highlights`, `matches`, `context` and `relatedLogs`.

Filters (`SearchFilters`), all optional. These are applied by the engine:

| Filter      | Description                                                                                          |
| ----------- | ---------------------------------------------------------------------------------------------------- |
| `levels`    | Only these levels.                                                                                   |
| `services`  | Only these app names.                                                                                |
| `traceIds`  | Only these trace IDs. Entries that have no trace ID are not excluded by this filter.                 |
| `timeRange` | `{ start, end? }` as dates or epoch milliseconds. Entries before `start` or after `end` are dropped. |
| `hasError`  | `true` keeps entries at level `error` or with an `error` field; `false` keeps the rest.              |
| `contexts`  | Only these context labels. Entries that have no context are not excluded by this filter.             |

::: warning Filters that are typed but not applied
`SearchFilters` also declares `userIds`, `sessionIds`, `excludePatterns`, `minSeverity` and `customFields`, and `TimeRange` declares `relative`. The current engine does not apply them, so filter those cases yourself on the returned results.
:::

Options (`SearchOptions`): `limit`, `offset`, `sortBy` (`'timestamp'`, `'level'`, `'score'` or `'relevance'`), `sortOrder`, `includeContext`, `contextSize`, `highlightMatches`, `findSimilar`, `correlate` and `semanticSearch`.

```ts
import { SearchManager } from 'logixia/search';

const searcher = new SearchManager();

const recentErrors = await searcher.search(
  'timeout',
  {
    levels: ['error', 'warn'],
    timeRange: { start: Date.now() - 60 * 60 * 1000 },
    hasError: true,
  },
  { limit: 20, highlightMatches: true }
);
console.log(recentErrors.length);
```

### Natural language

`naturalLanguageSearch(query)` turns a phrase into filters using pattern matching (it is rule-based, not a language model):

```ts
import { SearchManager } from 'logixia/search';

const searcher = new SearchManager();

const results = await searcher.naturalLanguageSearch('payment failed in the last 2 hours');
const parsed = await searcher.parseNaturalLanguageQuery(
  'what did user u_9 do in the last 30 minutes'
);
console.log(results.length, parsed.intent, parsed.confidence, parsed.filters);
```

It recognizes levels (`error`, `warn`, ...), `from the <name> service`, `user <id>`, `trace <id>`, `last N seconds`, `minutes`, `hours` or `days`, and error class names such as `TimeoutError`. The detected intent is one of `find_errors`, `trace_request`, `find_user_activity`, `performance_analysis`, `find_similar`, `time_range_query`, `correlation` or `general_search`.

Recognized filter words (`show`, `in`, `the`, `last`, `error`, `user`, `service` and similar) and the matched entities are removed, and what remains is searched as text. Phrase queries around words that appear in your messages. If nothing remains, for example `show errors in the last 2 hours`, the whole phrase is searched as text and usually matches nothing; use `search('', { levels: ['error'], timeRange })` for filter-only queries.

`getSuggestions(partial, limit?)` returns completion suggestions.

## Correlation

```ts
import { SearchManager } from 'logixia/search';

const searcher = new SearchManager();

const trace = await searcher.correlateByTraceId('trace-1');
console.log(trace.logs.length, trace.timeline.length, trace.summary?.errorCount);

const cascade = await searcher.analyzeErrorCascade('trace-1');
console.log(cascade.rootCause?.message, cascade.impactedServices);

const groups = await searcher.correlateByMultipleCriteria({ traceId: true, userId: true });
console.log(groups.size);
```

`findSimilarLogs(entry, limit?)` and `findRelatedLogs(entry, limit?)` return entries that look alike or share a trace, user, session or time window.

## Patterns and anomalies

`detectPatterns()` groups recurring messages into `LogPattern` records with a frequency and examples; `getPatterns()` returns those found so far. `detectAnomalies()` returns `AnomalyDetection` records with an `anomalyScore` and the reasons an entry stands out. Both throw if pattern recognition is disabled.

## Saved searches

`savePreset({ name, query, filters, options })` stores a search and returns it with an `id`; `getPresets(userId?)` lists them and `deletePreset(id)` removes one. Presets are kept in memory as well.

## Exporting results

```ts
import { SearchManager } from 'logixia/search';

const searcher = new SearchManager();
const results = await searcher.search('error');

const csv = await searcher.exportResults(results, {
  format: 'csv',
  fields: ['timestamp', 'level', 'message'],
});
console.log(csv);
```

Formats are `json`, `csv` and `text`. CSV output neutralizes values that a spreadsheet would run as a formula by prefixing them with a quote.

## Search from the command line

To search a log file without writing code, use the [`logixia` CLI](/guide/cli).
