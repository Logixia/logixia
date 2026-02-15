# 🔍 Smart Log Aggregation and Intelligent Search

## Overview

Logixia now includes a powerful intelligent search system that makes finding, analyzing, and correlating logs effortless. Built with natural language processing, pattern recognition, and advanced correlation capabilities, it transforms log analysis from a tedious task into an intuitive experience.

## 🌟 Key Features

### 1. **Natural Language Search**
Search logs using plain English queries instead of complex filter syntax.

```typescript
// Instead of complex filters, just ask:
const results = await searchManager.naturalLanguageSearch(
  'Show me all errors from the payment service in the last hour'
);
```

**Supported Queries:**
- "Show me all errors"
- "Find logs from user 12345"
- "What happened in the last 2 hours?"
- "Show slow queries from the database service"
- "Find logs related to payment processing"

### 2. **Intelligent Log Correlation**
Automatically find related logs across multiple dimensions:
- **Trace ID correlation**: Follow requests across microservices
- **User journey tracking**: See all logs for a specific user
- **Error cascade analysis**: Understand how errors propagate
- **Temporal correlation**: Group logs by time proximity
- **Service correlation**: Track activity across services

```typescript
// Find all logs for a trace ID
const correlated = await searchManager.correlateByTraceId('trace-123');
console.log(correlated.timeline);  // Chronological view
console.log(correlated.summary);   // Statistics and insights

// Multi-criteria correlation
const correlations = await searchManager.correlateByMultipleCriteria({
  traceId: true,
  userId: true,
  temporal: true,
  errorCascade: true,
});
```

### 3. **Pattern Recognition & Anomaly Detection**
Automatically detect patterns and unusual behavior in your logs.

```typescript
// Detect common patterns
const patterns = await searchManager.detectPatterns();
// Returns: message patterns, error patterns, timing patterns

// Find anomalies
const anomalies = await searchManager.detectAnomalies();
// Returns: unusual logs with anomaly scores and reasons
```

**Pattern Types:**
- **Message patterns**: Common log message templates
- **Error patterns**: Recurring error types
- **Timing patterns**: Peak activity hours
- **Behavioral patterns**: Unusual sequences

### 4. **Smart Filtering & Grouping**
Powerful filtering with intuitive syntax:

```typescript
const results = await searchManager.search('database error', {
  levels: ['error', 'warn'],
  services: ['api-gateway', 'database'],
  timeRange: {
    start: new Date(Date.now() - 3600000), // Last hour
  },
  hasError: true,
}, {
  limit: 50,
  sortBy: 'timestamp',
  includeContext: true,  // Get surrounding logs
  highlightMatches: true,
});
```

### 5. **Contextual Enhancement**
Get the full picture with contextual information:

```typescript
const results = await searchManager.search('timeout', undefined, {
  includeContext: true,
  contextSize: 10,  // 10 logs before and after
});

// Each result includes:
// - The matching log
// - Surrounding context
// - Related logs
// - Similarity scores
```

### 6. **Search Suggestions & Autocomplete**
Intelligent suggestions as you type:

```typescript
const suggestions = await searchManager.getSuggestions('err', 10);
// Returns: 'error', 'error_code', 'user_error', recent searches, etc.
```

### 7. **Search Presets**
Save and reuse common searches:

```typescript
// Save a preset
const preset = await searchManager.savePreset({
  name: 'Critical Errors',
  description: 'Production errors requiring immediate attention',
  query: 'critical',
  filters: { levels: ['error'] },
  options: { limit: 100 },
});

// Use presets
const presets = await searchManager.getPresets();
```

### 8. **Export Capabilities**
Export results in multiple formats:

```typescript
// JSON export
const json = await searchManager.exportResults(results, {
  format: 'json',
  fields: ['timestamp', 'level', 'message'],
});

// CSV export
const csv = await searchManager.exportResults(results, {
  format: 'csv',
  fields: ['timestamp', 'level', 'message'],
});

// Text export
const text = await searchManager.exportResults(results, {
  format: 'text',
  includeMetadata: true,
});
```

## 🚀 Quick Start

### Installation

The search functionality is included in the main Logixia package:

```bash
npm install logixia
# or
yarn add logixia
# or
pnpm add logixia
```

### Basic Usage

```typescript
import { SearchManager } from 'logixia';

// Initialize search manager
const searchManager = new SearchManager({
  enableNLP: true,
  enablePatternRecognition: true,
  enableCorrelation: true,
});

// Index your logs
await searchManager.indexLogs(myLogs);

// Start searching!
const results = await searchManager.search('error');
```

### Natural Language Search

```typescript
// Ask questions in plain English
const results = await searchManager.naturalLanguageSearch(
  'Show me database errors from the orders service today'
);

// The system automatically:
// 1. Understands your intent
// 2. Extracts filters (service, level, time)
// 3. Returns relevant results
```

## 📊 Real-World Use Cases

### Use Case 1: Debugging Production Issues

```typescript
// Find the error
const errors = await searchManager.search('payment failed', {
  levels: ['error'],
  timeRange: { start: incidentTime },
});

// Get the full context
const correlated = await searchManager.correlateByTraceId(
  errors[0].log.traceId
);

// Analyze the error cascade
const cascade = await searchManager.analyzeErrorCascade(
  errors[0].log.traceId
);

console.log('Root cause:', cascade.rootCause);
console.log('Impacted services:', cascade.impactedServices);
```

### Use Case 2: Performance Monitoring

```typescript
// Find slow operations
const slowOps = await searchManager.naturalLanguageSearch(
  'Show me all slow queries from the last 24 hours'
);

// Detect patterns
const patterns = await searchManager.detectPatterns();
const slowQueryPatterns = patterns.filter(
  p => p.category === 'performance'
);

// Get statistics
const stats = await searchManager.getStats();
```

### Use Case 3: User Activity Tracking

```typescript
// Track user journey
const userLogs = await searchManager.search('', {
  userIds: ['user123'],
}, {
  sortBy: 'timestamp',
  sortOrder: 'asc',
  includeContext: true,
});

// Find related sessions
const related = await searchManager.findRelatedLogs(userLogs[0].log);
```

### Use Case 4: Security Monitoring

```typescript
// Find suspicious activity
const suspicious = await searchManager.naturalLanguageSearch(
  'Find failed login attempts in the last hour'
);

// Detect anomalies
const anomalies = await searchManager.detectAnomalies();
const securityAnomalies = anomalies.filter(
  a => a.log.level === 'warn' || a.log.level === 'error'
);
```

## 🎯 Advanced Features

### Custom Search Pipelines

```typescript
// Parse query first
const parsed = await searchManager.parseNaturalLanguageQuery(query);

// Customize filters
parsed.filters.services = ['critical-service-1', 'critical-service-2'];

// Execute with custom options
const results = await searchManager.search(
  parsed.originalQuery,
  parsed.filters,
  { includeContext: true, correlate: true }
);
```

### Real-Time Search

```typescript
// Index logs as they arrive
logger.on('log', async (log) => {
  await searchManager.indexLog(log);
});

// Query recent logs
setInterval(async () => {
  const recent = await searchManager.search('', {
    timeRange: { start: new Date(Date.now() - 60000) },
  });
}, 5000);
```

### Batch Processing

```typescript
// Process large log volumes efficiently
const batchSize = 1000;
for (let i = 0; i < logs.length; i += batchSize) {
  const batch = logs.slice(i, i + batchSize);
  await searchManager.indexLogs(batch);
}

await searchManager.optimizeIndex();
```

## 📈 Performance Considerations

### Index Management

```typescript
// Configure index size limits
const searchManager = new SearchManager({
  maxIndexSize: 1000000,  // Max 1M logs
  autoOptimize: true,
});

// Periodically remove old logs
await searchManager.removeOldLogs(
  new Date(Date.now() - 7 * 24 * 60 * 60 * 1000)  // 7 days
);

// Manual optimization
await searchManager.optimizeIndex();
```

### Query Optimization

```typescript
// Use specific filters
const results = await searchManager.search('error', {
  levels: ['error'],
  services: ['payment'],
  timeRange: { start: new Date(Date.now() - 3600000) },
}, {
  limit: 50,  // Limit results
});

// Paginate large result sets
const page1 = await searchManager.search('error', undefined, {
  limit: 100,
  offset: 0,
});
```

### Memory Management

```typescript
// Monitor index size
const stats = await searchManager.getIndexStats();
console.log(`Size: ${stats.indexSize} bytes`);
console.log(`Documents: ${stats.totalDocuments}`);

// Clear when needed
if (stats.indexSize > 100_000_000) {
  await searchManager.clearIndex();
}
```

## 🔧 Configuration

### SearchManager Options

```typescript
const searchManager = new SearchManager({
  // Enable/disable features
  enableNLP: true,                    // Natural language processing
  enablePatternRecognition: true,     // Pattern detection
  enableCorrelation: true,            // Log correlation
  
  // Performance tuning
  maxIndexSize: 1000000,             // Maximum logs to index
  autoOptimize: true,                 // Auto-optimize index
});
```

### Search Options

```typescript
const options: SearchOptions = {
  limit: 100,                         // Max results
  offset: 0,                          // Pagination offset
  sortBy: 'timestamp',                // Sort field
  sortOrder: 'desc',                  // Sort direction
  includeContext: true,               // Include surrounding logs
  contextSize: 5,                     // Context size
  highlightMatches: true,             // Highlight matched terms
  findSimilar: true,                  // Find similar logs
  correlate: true,                    // Correlate results
  semanticSearch: true,               // Enable semantic search
};
```

## 📚 API Reference

See [SEARCH_DOCUMENTATION.md](./SEARCH_DOCUMENTATION.md) for complete API documentation.

## 🎓 Examples

Run the examples to see the search system in action:

```bash
# Quick start example
npm run dev:search

# Comprehensive demo
npm run dev:intelligent-search
```

## 🛠️ Integration

### Express.js

```typescript
import express from 'express';
import { SearchManager } from 'logixia';

const app = express();
const searchManager = new SearchManager();

app.get('/api/logs/search', async (req, res) => {
  const results = await searchManager.search(
    req.query.query as string,
    { levels: req.query.level ? [req.query.level as string] : undefined }
  );
  res.json(results);
});

app.get('/api/logs/nl-search', async (req, res) => {
  const results = await searchManager.naturalLanguageSearch(
    req.query.query as string
  );
  res.json(results);
});
```

### NestJS

```typescript
import { Injectable } from '@nestjs/common';
import { SearchManager } from 'logixia';

@Injectable()
export class LogSearchService {
  private searchManager = new SearchManager();

  async search(query: string, filters?: any) {
    return this.searchManager.search(query, filters);
  }

  async naturalLanguageSearch(query: string) {
    return this.searchManager.naturalLanguageSearch(query);
  }
}
```

## 🎯 Success Metrics

The intelligent search system is designed to achieve:

- **95%** relevant results in top 10 matches
- **80%** reduction in time to find relevant logs
- **90%** developer satisfaction with search experience
- **85%** query success rate for natural language searches

## 🚧 Roadmap

### Phase 4: Integration & Collaboration
- [ ] IDE extensions (VS Code, IntelliJ)
- [ ] Team sharing features
- [ ] External tool integrations (Slack, PagerDuty)
- [ ] Advanced visualization dashboards

### Future Enhancements
- [ ] Elasticsearch backend integration
- [ ] Machine learning-based ranking
- [ ] Real-time log streaming
- [ ] Cloud storage integration
- [ ] Advanced predictive analytics

## 💡 Tips & Best Practices

1. **Index regularly**: Keep your search index up to date
2. **Use specific filters**: Narrow down results for better performance
3. **Leverage NLP**: Natural language queries are powerful and intuitive
4. **Save presets**: Store frequently used searches
5. **Monitor index size**: Periodically clean old logs
6. **Use correlation**: Understanding relationships is key to debugging
7. **Enable all features**: NLP, pattern recognition, and correlation work best together

## 🤝 Contributing

We welcome contributions! Areas we'd love help with:
- Advanced NLP algorithms
- Machine learning models
- Visualization components
- Integration with external systems
- Performance optimizations

## 📄 License

MIT License - see [LICENSE](./LICENSE) for details

## 🙏 Acknowledgments

Special thanks to all contributors who made this intelligent search system possible!

---

**Ready to transform your log analysis experience?** Get started with Logixia's intelligent search today! 🚀
