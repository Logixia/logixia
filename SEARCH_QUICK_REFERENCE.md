# 🔍 Search Quick Reference

A quick reference guide for Logixia's intelligent search features.

## 🚀 Setup

```typescript
import { SearchManager } from 'logixia';

const searchManager = new SearchManager({
  enableNLP: true,                    // Natural language processing
  enablePatternRecognition: true,     // Pattern detection
  enableCorrelation: true,            // Log correlation
  maxIndexSize: 1000000,             // Max logs
  autoOptimize: true,                 // Auto-optimize
});
```

## 📝 Basic Operations

### Index Logs
```typescript
// Single log
await searchManager.indexLog(log);

// Multiple logs
await searchManager.indexLogs(logs);
```

### Simple Search
```typescript
// Basic text search
const results = await searchManager.search('error');

// With limit
const results = await searchManager.search('error', undefined, { limit: 50 });
```

### Natural Language Search
```typescript
const results = await searchManager.naturalLanguageSearch(
  'Show me all errors from the payment service in the last hour'
);
```

## 🎯 Filtering

### By Level
```typescript
await searchManager.search('', { 
  levels: ['error', 'warn'] 
});
```

### By Service
```typescript
await searchManager.search('', { 
  services: ['api-gateway', 'payment'] 
});
```

### By Time Range
```typescript
await searchManager.search('', {
  timeRange: {
    start: new Date(Date.now() - 3600000), // Last hour
    end: new Date(),
  }
});
```

### By User
```typescript
await searchManager.search('', { 
  userIds: ['user123'] 
});
```

### By Trace ID
```typescript
await searchManager.search('', { 
  traceIds: ['trace-abc-123'] 
});
```

### Multiple Filters
```typescript
await searchManager.search('timeout', {
  levels: ['error', 'warn'],
  services: ['api-gateway'],
  timeRange: { start: new Date(Date.now() - 3600000) },
  hasError: true,
});
```

## 🔗 Correlation

### By Trace ID
```typescript
const correlated = await searchManager.correlateByTraceId('trace-123');

console.log(correlated.logs);          // All logs
console.log(correlated.timeline);      // Chronological events
console.log(correlated.summary);       // Statistics
```

### Multi-Criteria
```typescript
const correlations = await searchManager.correlateByMultipleCriteria({
  traceId: true,
  userId: true,
  sessionId: true,
  temporal: true,
  errorCascade: true,
});
```

### Find Related Logs
```typescript
const related = await searchManager.findRelatedLogs(myLog, 10);

related.forEach(r => {
  console.log(r.relationship);  // 'same_trace', 'same_user', etc.
  console.log(r.score);         // Relevance score
  console.log(r.log);           // The related log
});
```

### Error Cascade Analysis
```typescript
const cascade = await searchManager.analyzeErrorCascade('trace-123');

console.log(cascade.rootCause);        // First error
console.log(cascade.cascade);          // All related errors
console.log(cascade.impactedServices); // Affected services
```

## 🔍 Advanced Search

### With Context
```typescript
const results = await searchManager.search('error', undefined, {
  includeContext: true,
  contextSize: 5,  // 5 logs before/after
});

results.forEach(r => {
  console.log(r.log);      // Main log
  console.log(r.context);  // Surrounding logs
});
```

### With Highlighting
```typescript
const results = await searchManager.search('database error', undefined, {
  highlightMatches: true,
});

results.forEach(r => {
  console.log(r.highlights);  // Matched terms
});
```

### Find Similar
```typescript
const similar = await searchManager.findSimilarLogs(referenceLog, 10);

similar.forEach(s => {
  console.log(s.similarity);       // 0-1 score
  console.log(s.matchedPatterns); // What matched
  console.log(s.reason);          // Explanation
});
```

### With Sorting
```typescript
await searchManager.search('error', undefined, {
  sortBy: 'timestamp',
  sortOrder: 'desc',  // or 'asc'
});
```

### With Pagination
```typescript
// Page 1
await searchManager.search('error', undefined, {
  limit: 50,
  offset: 0,
});

// Page 2
await searchManager.search('error', undefined, {
  limit: 50,
  offset: 50,
});
```

## 🎨 Pattern Recognition

### Detect Patterns
```typescript
const patterns = await searchManager.detectPatterns();

patterns.forEach(p => {
  console.log(p.pattern);    // Pattern template
  console.log(p.category);   // 'message', 'error', 'timing'
  console.log(p.frequency);  // Occurrence count
  console.log(p.examples);   // Sample logs
});
```

### Detect Anomalies
```typescript
const anomalies = await searchManager.detectAnomalies();

anomalies.forEach(a => {
  console.log(a.anomalyScore);  // 0-1 score
  console.log(a.reason);        // Why anomalous
  console.log(a.deviations);    // What's unusual
  console.log(a.log);           // The anomalous log
});
```

### Get Patterns
```typescript
const patterns = searchManager.getPatterns();
```

## 💡 Suggestions

### Autocomplete
```typescript
const suggestions = await searchManager.getSuggestions('err', 10);

suggestions.forEach(s => {
  console.log(s.text);      // Suggestion text
  console.log(s.type);      // 'field', 'value', 'query_history'
  console.log(s.category);  // Category
});
```

## 🔖 Presets

### Save Preset
```typescript
const preset = await searchManager.savePreset({
  name: 'Critical Errors',
  description: 'Production errors requiring attention',
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
```

### Get Presets
```typescript
// All presets
const presets = await searchManager.getPresets();

// User presets
const myPresets = await searchManager.getPresets('user123');
```

### Delete Preset
```typescript
await searchManager.deletePreset(presetId);
```

## 📤 Export

### JSON Export
```typescript
const json = await searchManager.exportResults(results, {
  format: 'json',
  includeMetadata: true,
  fields: ['timestamp', 'level', 'message', 'appName'],
});
```

### CSV Export
```typescript
const csv = await searchManager.exportResults(results, {
  format: 'csv',
  fields: ['timestamp', 'level', 'message'],
});
```

### Text Export
```typescript
const text = await searchManager.exportResults(results, {
  format: 'text',
  includeMetadata: true,
});
```

## 📊 Statistics

### Search Stats
```typescript
const stats = await searchManager.getStats();

console.log(stats.totalResults);   // Total logs
console.log(stats.executionTime);  // Last query time
console.log(stats.indexSize);      // Index size
console.log(stats.topTerms);       // Common terms
```

### Index Stats
```typescript
const stats = await searchManager.getIndexStats();

console.log(stats.totalDocuments); // Total logs
console.log(stats.indexSize);      // Size in bytes
console.log(stats.lastOptimized);  // Last optimization
```

## 🗑️ Maintenance

### Clear Index
```typescript
await searchManager.clearIndex();
```

### Optimize Index
```typescript
await searchManager.optimizeIndex();
```

### Remove Old Logs
```typescript
// Remove logs older than 7 days
const removed = await searchManager.removeOldLogs(
  new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)
);
console.log(`Removed ${removed} logs`);
```

## 🎯 Natural Language Examples

```typescript
// Error finding
"Show me all errors"
"Find errors from the payment service"
"What errors happened today?"

// User tracking
"Show logs for user 12345"
"What did user123 do?"
"Find all activity from user xyz"

// Time-based
"Logs from the last hour"
"Show me logs from today"
"Find logs from the past 2 hours"

// Service-specific
"Show logs from payment service"
"Find all logs from api-gateway"

// Performance
"Show slow queries"
"Find performance issues"
"Show operations that took too long"

// Correlation
"What happened before the crash?"
"Show logs related to this error"
"Find all logs for trace abc123"
```

## ⚡ Common Patterns

### Debug Production Issue
```typescript
// 1. Find the error
const errors = await searchManager.search('error', {
  timeRange: { start: incidentTime },
});

// 2. Get full context
const correlated = await searchManager.correlateByTraceId(
  errors[0].log.traceId
);

// 3. Analyze cascade
const cascade = await searchManager.analyzeErrorCascade(
  errors[0].log.traceId
);
```

### Monitor User Activity
```typescript
// Get all user logs
const userLogs = await searchManager.search('', {
  userIds: ['user123'],
}, {
  sortBy: 'timestamp',
  sortOrder: 'asc',
  includeContext: true,
});
```

### Find Performance Issues
```typescript
// Search for slow operations
const slowOps = await searchManager.naturalLanguageSearch(
  'Show me all slow queries from the last 24 hours'
);

// Detect patterns
const patterns = await searchManager.detectPatterns();
```

### Track Request Flow
```typescript
// Follow a request through services
const flow = await searchManager.correlateByTraceId('trace-123');

// View timeline
flow.timeline.forEach(event => {
  console.log(`[${event.eventType}] ${event.log.message}`);
});
```

## 🎨 Configuration Tips

```typescript
// For large volumes
const searchManager = new SearchManager({
  maxIndexSize: 5000000,  // 5M logs
  autoOptimize: true,
  enableNLP: true,
  enablePatternRecognition: false,  // Disable if not needed
  enableCorrelation: true,
});

// For real-time search
const searchManager = new SearchManager({
  maxIndexSize: 100000,   // Smaller index
  autoOptimize: true,
  enableNLP: true,
  enablePatternRecognition: true,
  enableCorrelation: true,
});
```

## 🔗 Useful Links

- **Full Documentation**: `SEARCH_DOCUMENTATION.md`
- **Feature Overview**: `SEARCH_FEATURE.md`
- **Examples**: `examples/search-quickstart.ts`
- **Comprehensive Demo**: `examples/intelligent-search.ts`

## 🎓 Run Examples

```bash
# Quick start
npm run dev:search

# Full demo
npm run dev:intelligent-search
```

---

**Need more help?** Check the full documentation in `SEARCH_DOCUMENTATION.md`
