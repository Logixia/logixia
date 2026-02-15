# 🔍 Intelligent Log Search Documentation

## Overview

Logixia's intelligent log search system provides powerful capabilities for finding, analyzing, and correlating logs. It includes natural language processing, pattern recognition, anomaly detection, and advanced correlation features.

## Table of Contents

- [Quick Start](#quick-start)
- [Core Features](#core-features)
- [API Reference](#api-reference)
- [Search Examples](#search-examples)
- [Advanced Usage](#advanced-usage)
- [Performance Tips](#performance-tips)

## Quick Start

### Installation

```typescript
import { SearchManager } from 'logixia/search';

// Create search manager with default settings
const searchManager = new SearchManager();

// Or with custom configuration
const searchManager = new SearchManager({
  enableNLP: true,
  enablePatternRecognition: true,
  enableCorrelation: true,
  maxIndexSize: 1000000,
  autoOptimize: true,
});
```

### Basic Usage

```typescript
// Index logs
await searchManager.indexLogs(myLogs);

// Simple search
const results = await searchManager.search('error');

// Natural language search
const nlResults = await searchManager.naturalLanguageSearch(
  'Show me all errors from the payment service in the last hour'
);
```

## Core Features

### 1. Natural Language Search

Search logs using plain English queries. The system automatically understands intent and extracts filters.

**Supported Query Types:**
- Error finding: "Show me all errors"
- Time-based: "Logs from the last hour"
- Service-specific: "Find logs from payment service"
- User tracking: "What did user123 do?"
- Performance: "Show slow queries"

**Example:**
```typescript
// Query in natural language
const results = await searchManager.naturalLanguageSearch(
  'Find all database errors from the orders service today'
);

// Parse query to see what was extracted
const parsed = await searchManager.parseNaturalLanguageQuery(
  'Show errors from user 12345 in the last 2 hours'
);

console.log(parsed.intent);      // 'find_errors'
console.log(parsed.filters);     // { levels: ['error'], userIds: ['12345'], ... }
console.log(parsed.confidence);  // 0.85
```

### 2. Advanced Filtering

Precise control over search results with comprehensive filtering options.

```typescript
const results = await searchManager.search('timeout', {
  levels: ['error', 'warn'],
  services: ['api-gateway', 'database'],
  traceIds: ['req-123'],
  timeRange: {
    start: new Date(Date.now() - 60 * 60 * 1000), // Last hour
    end: new Date(),
  },
  userIds: ['user123'],
  hasError: true,
  customFields: {
    database: 'postgres',
  },
}, {
  limit: 50,
  offset: 0,
  sortBy: 'timestamp',
  sortOrder: 'desc',
  includeContext: true,
  contextSize: 5,
  highlightMatches: true,
});
```

### 3. Log Correlation

Find related logs across multiple criteria.

#### By Trace ID
```typescript
const correlated = await searchManager.correlateByTraceId('trace-123');

console.log(correlated.logs.length);          // All logs with this trace ID
console.log(correlated.summary.duration);     // Total duration
console.log(correlated.summary.errorCount);   // Number of errors
console.log(correlated.timeline);             // Chronological events
```

#### By Multiple Criteria
```typescript
const correlations = await searchManager.correlateByMultipleCriteria({
  traceId: true,
  userId: true,
  sessionId: true,
  temporal: true,        // Group by time proximity
  errorCascade: true,    // Find error cascades
});

for (const [key, corr] of correlations.entries()) {
  console.log(`${key}: ${corr.logs.length} logs`);
}
```

#### Find Related Logs
```typescript
const relatedLogs = await searchManager.findRelatedLogs(myLog, 10);

relatedLogs.forEach(related => {
  console.log(related.relationship);  // 'same_trace', 'same_user', etc.
  console.log(related.score);         // Relevance score
  console.log(related.log);           // The related log entry
});
```

### 4. Pattern Recognition

Automatically detect patterns and anomalies in logs.

#### Detect Patterns
```typescript
const patterns = await searchManager.detectPatterns();

patterns.forEach(pattern => {
  console.log(pattern.pattern);      // The pattern template
  console.log(pattern.frequency);    // How often it appears
  console.log(pattern.category);     // 'message', 'error', 'timing'
  console.log(pattern.examples);     // Sample logs matching pattern
});
```

#### Detect Anomalies
```typescript
const anomalies = await searchManager.detectAnomalies();

anomalies.forEach(anomaly => {
  console.log(anomaly.anomalyScore);  // 0-1 score
  console.log(anomaly.reason);        // Why it's anomalous
  console.log(anomaly.deviations);    // What's unusual
  console.log(anomaly.log);           // The anomalous log
});
```

### 5. Similar Log Search

Find logs similar to a given log entry.

```typescript
const similar = await searchManager.findSimilarLogs(referenceLog, 10);

similar.forEach(sim => {
  console.log(sim.similarity);       // 0-1 similarity score
  console.log(sim.matchedPatterns);  // What matched
  console.log(sim.reason);           // Explanation
  console.log(sim.log);              // The similar log
});
```

### 6. Search Suggestions

Get intelligent autocomplete suggestions.

```typescript
const suggestions = await searchManager.getSuggestions('err', 10);

suggestions.forEach(suggestion => {
  console.log(suggestion.text);      // Suggestion text
  console.log(suggestion.type);      // 'field', 'value', 'query_history'
  console.log(suggestion.category);  // Category
});
```

### 7. Search Presets

Save and reuse common searches.

```typescript
// Save a preset
const preset = await searchManager.savePreset({
  name: 'Critical Errors',
  description: 'High-priority errors in production',
  query: 'critical',
  filters: {
    levels: ['error'],
    services: ['payment', 'orders'],
  },
  options: {
    limit: 100,
    includeContext: true,
  },
});

// Get all presets
const presets = await searchManager.getPresets();

// Get user-specific presets
const myPresets = await searchManager.getPresets('user123');

// Delete a preset
await searchManager.deletePreset(preset.id);
```

### 8. Export Results

Export search results in multiple formats.

```typescript
const results = await searchManager.search('error');

// Export as JSON
const json = await searchManager.exportResults(results, {
  format: 'json',
  includeMetadata: true,
  fields: ['timestamp', 'level', 'message', 'appName'],
});

// Export as CSV
const csv = await searchManager.exportResults(results, {
  format: 'csv',
  fields: ['timestamp', 'level', 'message'],
});

// Export as text
const text = await searchManager.exportResults(results, {
  format: 'text',
  includeMetadata: true,
});
```

### 9. Error Cascade Analysis

Analyze how errors propagate through your system.

```typescript
const analysis = await searchManager.analyzeErrorCascade('trace-123');

console.log(analysis.rootCause);        // The initial error
console.log(analysis.cascade);          // All related errors
console.log(analysis.impactedServices); // Affected services
```

## API Reference

### SearchManager

Main class for managing log search operations.

#### Constructor

```typescript
constructor(config?: SearchManagerConfig)
```

**Config Options:**
- `enableNLP`: Enable natural language processing (default: `true`)
- `enablePatternRecognition`: Enable pattern detection (default: `true`)
- `enableCorrelation`: Enable log correlation (default: `true`)
- `maxIndexSize`: Maximum logs to index (default: `1000000`)
- `autoOptimize`: Auto-optimize index (default: `true`)

#### Methods

##### indexLogs
```typescript
async indexLogs(logs: LogEntry[]): Promise<void>
```
Index multiple logs for searching.

##### indexLog
```typescript
async indexLog(log: LogEntry): Promise<void>
```
Index a single log entry.

##### search
```typescript
async search(
  query: string,
  filters?: SearchFilters,
  options?: SearchOptions
): Promise<SearchResult[]>
```
Perform a full-text search.

##### naturalLanguageSearch
```typescript
async naturalLanguageSearch(query: string): Promise<SearchResult[]>
```
Search using natural language queries.

##### correlateByTraceId
```typescript
async correlateByTraceId(traceId: string): Promise<CorrelatedLogs>
```
Find all logs with the same trace ID.

##### findSimilarLogs
```typescript
async findSimilarLogs(logEntry: LogEntry, limit?: number): Promise<SimilarLog[]>
```
Find logs similar to the given log.

##### findRelatedLogs
```typescript
async findRelatedLogs(log: LogEntry, limit?: number): Promise<RelatedLog[]>
```
Find logs related through various relationships.

##### getSuggestions
```typescript
async getSuggestions(partialQuery: string, limit?: number): Promise<SearchSuggestion[]>
```
Get search suggestions for autocomplete.

##### detectPatterns
```typescript
async detectPatterns(): Promise<LogPattern[]>
```
Detect patterns in indexed logs.

##### detectAnomalies
```typescript
async detectAnomalies(): Promise<AnomalyDetection[]>
```
Detect anomalous log entries.

##### savePreset
```typescript
async savePreset(preset: Omit<SearchPreset, 'id' | 'createdAt' | 'updatedAt'>): Promise<SearchPreset>
```
Save a search preset.

##### exportResults
```typescript
async exportResults(results: SearchResult[], options: ExportOptions): Promise<string>
```
Export search results in various formats.

##### clearIndex
```typescript
async clearIndex(): Promise<void>
```
Clear all indexed data.

##### optimizeIndex
```typescript
async optimizeIndex(): Promise<void>
```
Manually optimize the search index.

## Search Examples

### Example 1: Finding Errors

```typescript
// Find all errors
const errors = await searchManager.search('', {
  levels: ['error'],
});

// Find errors in a specific service
const serviceErrors = await searchManager.search('', {
  levels: ['error'],
  services: ['payment-service'],
});

// Find recent errors
const recentErrors = await searchManager.search('', {
  levels: ['error'],
  timeRange: {
    start: new Date(Date.now() - 15 * 60 * 1000), // Last 15 minutes
  },
});
```

### Example 2: Tracking User Activity

```typescript
// Find all logs for a specific user
const userLogs = await searchManager.search('', {
  userIds: ['user123'],
}, {
  sortBy: 'timestamp',
  sortOrder: 'asc',
});

// Natural language query
const userActivity = await searchManager.naturalLanguageSearch(
  'What did user123 do in the last hour?'
);
```

### Example 3: Performance Analysis

```typescript
// Find slow queries
const slowQueries = await searchManager.search('slow query');

// Find performance issues
const perfIssues = await searchManager.naturalLanguageSearch(
  'Show me all performance problems from the database service'
);
```

### Example 4: Debugging with Context

```typescript
// Search with surrounding context
const results = await searchManager.search('null pointer', undefined, {
  includeContext: true,
  contextSize: 10,  // 10 logs before and after
});

results.forEach(result => {
  console.log('Main log:', result.log.message);
  console.log('Context logs:', result.context);
});
```

## Advanced Usage

### Custom Search Pipeline

```typescript
// Parse query
const parsed = await searchManager.parseNaturalLanguageQuery(query);

// Adjust filters
parsed.filters.levels = ['error', 'warn'];

// Perform search with custom options
const results = await searchManager.search(
  parsed.originalQuery,
  parsed.filters,
  {
    limit: 200,
    includeContext: true,
    highlightMatches: true,
    correlate: true,
  }
);
```

### Batch Processing

```typescript
// Index logs in batches for better performance
const batchSize = 1000;
for (let i = 0; i < logs.length; i += batchSize) {
  const batch = logs.slice(i, i + batchSize);
  await searchManager.indexLogs(batch);
}

// Optimize after batch processing
await searchManager.optimizeIndex();
```

### Real-Time Search

```typescript
// Add logs as they come in
logger.on('log', async (log) => {
  await searchManager.indexLog(log);
});

// Search the latest logs
const latestErrors = await searchManager.search('', {
  levels: ['error'],
  timeRange: {
    start: new Date(Date.now() - 60000), // Last minute
  },
});
```

## Performance Tips

### 1. Index Management

```typescript
// Set appropriate max index size
const searchManager = new SearchManager({
  maxIndexSize: 500000, // Adjust based on memory
});

// Periodically remove old logs
await searchManager.removeOldLogs(
  new Date(Date.now() - 7 * 24 * 60 * 60 * 1000) // Older than 7 days
);

// Manual optimization for large indices
await searchManager.optimizeIndex();
```

### 2. Query Optimization

```typescript
// Use specific filters to narrow results
const results = await searchManager.search('error', {
  levels: ['error'],
  services: ['payment'],
  timeRange: { start: new Date(Date.now() - 3600000) },
}, {
  limit: 50, // Limit results
});

// Use pagination for large result sets
const page1 = await searchManager.search('error', undefined, {
  limit: 100,
  offset: 0,
});

const page2 = await searchManager.search('error', undefined, {
  limit: 100,
  offset: 100,
});
```

### 3. Caching Strategies

```typescript
// Save frequently used searches as presets
await searchManager.savePreset({
  name: 'Today Errors',
  query: '',
  filters: {
    levels: ['error'],
    timeRange: {
      start: new Date(new Date().setHours(0, 0, 0, 0)),
    },
  },
  options: { limit: 100 },
});
```

### 4. Memory Management

```typescript
// Monitor index size
const stats = await searchManager.getIndexStats();
console.log(`Index size: ${stats.indexSize} bytes`);
console.log(`Total documents: ${stats.totalDocuments}`);

// Clear when needed
if (stats.indexSize > 100_000_000) { // 100MB
  await searchManager.clearIndex();
}
```

## Integration Examples

### Express.js Integration

```typescript
import express from 'express';
import { SearchManager } from 'logixia/search';

const app = express();
const searchManager = new SearchManager();

// Search endpoint
app.get('/api/logs/search', async (req, res) => {
  const { query, level, service, limit } = req.query;
  
  const results = await searchManager.search(query as string, {
    levels: level ? [level as string] : undefined,
    services: service ? [service as string] : undefined,
  }, {
    limit: parseInt(limit as string) || 50,
  });
  
  res.json(results);
});

// Natural language search endpoint
app.get('/api/logs/nl-search', async (req, res) => {
  const { query } = req.query;
  const results = await searchManager.naturalLanguageSearch(query as string);
  res.json(results);
});
```

### NestJS Integration

```typescript
import { Injectable } from '@nestjs/common';
import { SearchManager } from 'logixia/search';

@Injectable()
export class LogSearchService {
  private searchManager: SearchManager;

  constructor() {
    this.searchManager = new SearchManager({
      enableNLP: true,
      enablePatternRecognition: true,
      enableCorrelation: true,
    });
  }

  async search(query: string, filters?: any) {
    return this.searchManager.search(query, filters);
  }

  async naturalLanguageSearch(query: string) {
    return this.searchManager.naturalLanguageSearch(query);
  }
}
```

## Troubleshooting

### High Memory Usage

- Reduce `maxIndexSize`
- Clear old logs regularly with `removeOldLogs()`
- Disable features you don't need

### Slow Search

- Add more specific filters
- Reduce result limits
- Optimize index with `optimizeIndex()`
- Use time-based filters

### Low Accuracy

- Increase training data (more logs)
- Use specific search terms
- Combine multiple search criteria
- Enable NLP for better query understanding

## Future Enhancements

- Elasticsearch integration
- Machine learning-based search ranking
- Real-time log streaming
- Advanced visualization
- Team collaboration features
- Cloud storage integration

## Support

For issues, questions, or contributions, please visit:
- GitHub: https://github.com/Logixia/logixia
- Documentation: https://github.com/Logixia/logixia#readme
