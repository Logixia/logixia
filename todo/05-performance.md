# 05 — Performance

> Logixia performs fine for typical applications (< 10 k log entries in memory,
> < 1 000 req/s). The issues below matter when volume grows.

---

## PERF-01 🟡 O(n) search on every query — no index

**File:** `src/search/core/basic-search-engine.ts`
**Current behaviour:** Every call to `search()` iterates the entire in-memory log
array linearly. At 100 k entries, a simple text query scans 100 k objects.

### Benchmark the problem first

```typescript
// test/perf/search-benchmark.ts
import { BasicSearchEngine } from '../../src/search/core/basic-search-engine';

const engine = new BasicSearchEngine({ maxIndexSize: 500_000 });

// Seed 100k entries
for (let i = 0; i < 100_000; i++) {
  engine.indexLog({ /* ... */ });
}

console.time('search-100k');
engine.search('error database connection', { limit: 50 });
console.timeEnd('search-100k');
// Expected: < 50 ms — if > 500 ms, we have a problem
```

### Fix — inverted index for text fields

```typescript
class BasicSearchEngine {
  // Existing
  private logs: LogEntry[] = [];

  // ADD: inverted index
  private wordIndex = new Map<string, Set<number>>();  // word → array positions

  indexLog(entry: LogEntry): void {
    const position = this.logs.length;
    this.logs.push(entry);

    // Index all words in message
    const words = tokenize(entry.message);
    for (const word of words) {
      const set = this.wordIndex.get(word) ?? new Set<number>();
      set.add(position);
      this.wordIndex.set(word, set);
    }
  }

  private performTextSearch(query: string): LogEntry[] {
    const words = tokenize(query);
    if (words.length === 0) return this.logs;

    // Intersect candidate sets (AND semantics)
    let candidates: Set<number> | null = null;
    for (const word of words) {
      const set = this.wordIndex.get(word) ?? new Set<number>();
      candidates = candidates === null
        ? new Set(set)
        : new Set([...candidates].filter(i => set.has(i)));
    }

    return [...(candidates ?? new Set())]
      .map(i => this.logs[i])
      .filter(Boolean) as LogEntry[];
  }
}
```

With an inverted index, text search drops from O(n) to O(k) where k is the number
of matching documents — typically much smaller than n.

---

## PERF-02 🟡 `suggestionCache` and `searchHistory` grow without eviction

**File:** `src/search/core/basic-search-engine.ts`

```typescript
// Current
private suggestionCache = new Map<string, SearchSuggestion[]>();
private searchHistory: string[] = [];
```

Neither structure has a size cap. In a long-running process, these maps grow forever.

### Fix — use a bounded LRU cache

```typescript
class LRUCache<K, V> {
  private map = new Map<K, V>();
  constructor(private readonly maxSize: number) {}

  get(key: K): V | undefined {
    const value = this.map.get(key);
    if (value !== undefined) {
      // Move to end (most recently used)
      this.map.delete(key);
      this.map.set(key, value);
    }
    return value;
  }

  set(key: K, value: V): void {
    if (this.map.has(key)) this.map.delete(key);
    else if (this.map.size >= this.maxSize) {
      // Evict least recently used (first entry)
      this.map.delete(this.map.keys().next().value!);
    }
    this.map.set(key, value);
  }
}

// Usage
private suggestionCache = new LRUCache<string, SearchSuggestion[]>(500);
private searchHistory: string[] = [];     // keep last 100 queries
private readonly MAX_HISTORY = 100;

// In addToHistory()
if (this.searchHistory.length >= this.MAX_HISTORY) {
  this.searchHistory.shift();
}
this.searchHistory.push(query);
```

---

## PERF-03 🟡 `FileTransport.writeStream` — synchronous `appendFileSync` fallback

**File:** `src/transports/file.transport.ts`

If the write stream is not yet initialised, some code paths fall back to
`fs.appendFileSync()` which is synchronous and blocks the event loop.

### Fix — always write through the stream; queue if not ready

```typescript
private queue: LogEntry[] = [];
private streamReady = false;

private initStream(): void {
  this.writeStream = createWriteStream(this.filePath, { flags: 'a', encoding: 'utf-8' });
  this.writeStream.on('open', () => {
    this.streamReady = true;
    // Drain queued entries
    for (const entry of this.queue) {
      this.writeStream!.write(this.formatEntry(entry) + '\n');
    }
    this.queue = [];
  });
}

async write(entry: LogEntry): Promise<void> {
  if (!this.streamReady) {
    this.queue.push(entry);
    return;
  }
  this.batch.push(entry);
  if (this.batch.length >= this.batchSize) {
    await this.flushBatch();
  }
}
```

---

## PERF-04 🟡 `TransportManager` writes to all transports sequentially

**File:** `src/transports/transport.manager.ts`

```typescript
// Current — waits for each transport before starting the next
for (const transport of this.transports) {
  await transport.write(entry);   // sequential
}
```

If you have 3 transports (console + file + DB), each taking 1ms/5ms/20ms, the total
per-log cost is 26ms instead of 20ms.

### Fix — write to all transports concurrently

```typescript
async write(entry: LogEntry): Promise<void> {
  const results = await Promise.allSettled(
    this.transports.map(t => t.write(entry))
  );

  // Report failures without blocking
  for (const [i, result] of results.entries()) {
    if (result.status === 'rejected') {
      internalError(
        `Transport "${this.transports[i]?.id}" write failed`,
        result.reason,
      );
      this.metrics[i]!.totalErrors++;
    }
  }
}
```

Note: Use `Promise.allSettled` (not `Promise.all`) so one failing transport never
prevents others from receiving the log entry.

---

## PERF-05 🟢 Pattern recognition runs on every indexed log — expensive for high volume

**File:** `src/search/engines/pattern-recognition-engine.ts`

The `PatternRecognitionEngine.analyzeLog()` method runs on every log as it's
indexed. For 10 k logs/sec this becomes a hot path.

### Fix — batch pattern analysis and run on a micro-task

```typescript
class PatternRecognitionEngine {
  private pendingAnalysis: LogEntry[] = [];
  private analysisScheduled = false;

  indexLog(entry: LogEntry): void {
    this.pendingAnalysis.push(entry);
    if (!this.analysisScheduled) {
      this.analysisScheduled = true;
      setImmediate(() => this.flushAnalysis());
    }
  }

  private flushAnalysis(): void {
    const batch = this.pendingAnalysis.splice(0);
    this.analysisScheduled = false;
    for (const entry of batch) {
      this.runPatternMatching(entry);
    }
  }
}
```

This defers CPU work to idle time and batches it, reducing the impact on the
logging hot path.

---

## PERF-06 🟢 `CorrelationEngine.findRelated()` — linear scan per call

**File:** `src/search/engines/correlation-engine.ts`

### Fix — maintain a secondary index by traceId, userId, and sessionId

```typescript
class CorrelationEngine {
  private byTraceId  = new Map<string, LogEntry[]>();
  private byUserId   = new Map<string, LogEntry[]>();
  private bySessionId = new Map<string, LogEntry[]>();

  indexLog(entry: LogEntry): void {
    if (entry.traceId)   appendToMap(this.byTraceId,   entry.traceId,   entry);
    if (entry.userId)    appendToMap(this.byUserId,    entry.userId,    entry);
    if (entry.sessionId) appendToMap(this.bySessionId, entry.sessionId, entry);
  }

  findByTrace(traceId: string): LogEntry[] {
    return this.byTraceId.get(traceId) ?? [];
  }
}
```

O(1) lookup instead of O(n).

---

## Performance Budget (target for v1.3.0)

| Operation | Max acceptable latency |
|-----------|----------------------|
| `logger.info()` call (console transport) | < 0.5 ms |
| `logger.info()` call (file transport, batched) | < 0.1 ms |
| `search()` on 100 k entries, text query | < 50 ms |
| `search()` on 100 k entries, filter-only | < 10 ms |
| `findRelated()` by traceId | < 5 ms |
| `logger.flush()` 1 k batched entries | < 100 ms |

Add these as Jest performance tests using `performance.now()`.
