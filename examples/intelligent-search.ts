/**
 * Example: Intelligent Log Search
 * 
 * Demonstrates the smart log aggregation and intelligent search capabilities
 */

import { createLogger, LogEntry } from '../src';
import { SearchManager } from '../src/search';

async function main() {
  console.log('=== Intelligent Log Search Demo ===\n');

  // Create logger and search manager
  const logger = createLogger({
    appName: 'SearchDemo',
    environment: 'development',
  });

  const searchManager = new SearchManager({
    enableNLP: true,
    enablePatternRecognition: true,
    enableCorrelation: true,
  });

  // Generate sample logs
  console.log('1. Generating sample logs...');
  const sampleLogs = await generateSampleLogs(logger);
  
  // Index the logs
  console.log('2. Indexing logs...');
  await searchManager.indexLogs(sampleLogs);
  
  const stats = await searchManager.getStats();
  console.log(`   Indexed ${stats.totalResults} logs\n`);

  // Example 1: Basic text search
  console.log('=== Example 1: Basic Text Search ===');
  const basicResults = await searchManager.search('error', undefined, {
    limit: 5,
    highlightMatches: true,
  });
  
  console.log(`Found ${basicResults.length} results for "error":`);
  basicResults.slice(0, 3).forEach((result, i) => {
    console.log(`  ${i + 1}. [${result.log.level}] ${result.log.message}`);
    console.log(`     Score: ${result.score.toFixed(2)}`);
  });
  console.log();

  // Example 2: Natural language search
  console.log('=== Example 2: Natural Language Search ===');
  const nlQueries = [
    'Show me all errors from the last hour',
    'Find logs from the payment service',
    'What happened to user ID user123?',
  ];

  for (const query of nlQueries) {
    console.log(`Query: "${query}"`);
    const parsed = await searchManager.parseNaturalLanguageQuery(query);
    console.log(`  Intent: ${parsed.intent}`);
    console.log(`  Confidence: ${parsed.confidence.toFixed(2)}`);
    console.log(`  Filters: ${JSON.stringify(parsed.filters, null, 2)}`);
    
    const results = await searchManager.naturalLanguageSearch(query);
    console.log(`  Results: ${results.length} logs found\n`);
  }

  // Example 3: Advanced filtering
  console.log('=== Example 3: Advanced Filtering ===');
  const filteredResults = await searchManager.search('', {
    levels: ['error', 'warn'],
    timeRange: {
      start: new Date(Date.now() - 60 * 60 * 1000), // Last hour
    },
    hasError: true,
  }, {
    limit: 10,
    sortBy: 'timestamp',
    sortOrder: 'desc',
  });
  
  console.log(`Found ${filteredResults.length} errors/warnings in the last hour`);
  filteredResults.slice(0, 3).forEach((result, i) => {
    console.log(`  ${i + 1}. [${result.log.timestamp}] ${result.log.message}`);
  });
  console.log();

  // Example 4: Log correlation by trace ID
  console.log('=== Example 4: Log Correlation by Trace ID ===');
  const traceId = sampleLogs.find(l => l.traceId)?.traceId;
  if (traceId) {
    const correlated = await searchManager.correlateByTraceId(traceId);
    console.log(`Trace ID: ${traceId}`);
    console.log(`  Total logs: ${correlated.logs.length}`);
    console.log(`  Services involved: ${correlated.summary?.services.join(', ')}`);
    console.log(`  Duration: ${correlated.summary?.duration}ms`);
    console.log(`  Errors: ${correlated.summary?.errorCount}`);
    console.log('  Timeline:');
    correlated.timeline.slice(0, 5).forEach((event, i) => {
      console.log(`    ${i + 1}. [${event.eventType}] ${event.log.message}`);
    });
  }
  console.log();

  // Example 5: Find similar logs
  console.log('=== Example 5: Find Similar Logs ===');
  const errorLog = sampleLogs.find(l => l.level === 'error');
  if (errorLog) {
    console.log(`Reference log: ${errorLog.message}`);
    const similar = await searchManager.findSimilarLogs(errorLog, 5);
    console.log(`Found ${similar.length} similar logs:`);
    similar.forEach((sim, i) => {
      console.log(`  ${i + 1}. Similarity: ${sim.similarity.toFixed(2)}`);
      console.log(`     ${sim.log.message}`);
      console.log(`     Reason: ${sim.reason}`);
    });
  }
  console.log();

  // Example 6: Search suggestions
  console.log('=== Example 6: Search Suggestions ===');
  const partialQueries = ['err', 'user', 'pay'];
  
  for (const partial of partialQueries) {
    const suggestions = await searchManager.getSuggestions(partial, 5);
    console.log(`Suggestions for "${partial}":`);
    suggestions.forEach((sugg, i) => {
      console.log(`  ${i + 1}. [${sugg.type}] ${sugg.text}`);
    });
    console.log();
  }

  // Example 7: Pattern detection
  console.log('=== Example 7: Pattern Detection ===');
  const patterns = await searchManager.detectPatterns();
  console.log(`Detected ${patterns.length} patterns:`);
  patterns.slice(0, 5).forEach((pattern, i) => {
    console.log(`  ${i + 1}. Category: ${pattern.category}`);
    console.log(`     Pattern: ${pattern.pattern}`);
    console.log(`     Frequency: ${pattern.frequency}`);
  });
  console.log();

  // Example 8: Anomaly detection
  console.log('=== Example 8: Anomaly Detection ===');
  const anomalies = await searchManager.detectAnomalies();
  console.log(`Detected ${anomalies.length} anomalies:`);
  anomalies.slice(0, 3).forEach((anomaly, i) => {
    console.log(`  ${i + 1}. Score: ${anomaly.anomalyScore.toFixed(2)}`);
    console.log(`     Log: ${anomaly.log.message}`);
    console.log(`     Reason: ${anomaly.reason}`);
  });
  console.log();

  // Example 9: Save and use search presets
  console.log('=== Example 9: Search Presets ===');
  const preset = await searchManager.savePreset({
    name: 'Critical Errors',
    description: 'All critical errors from production',
    query: 'critical',
    filters: {
      levels: ['error'],
    },
    options: {
      limit: 50,
      includeContext: true,
    },
  });
  
  console.log(`Saved preset: "${preset.name}"`);
  console.log(`  ID: ${preset.id}`);
  
  const presets = await searchManager.getPresets();
  console.log(`\nAll saved presets (${presets.length}):`);
  presets.forEach((p, i) => {
    console.log(`  ${i + 1}. ${p.name} - ${p.description}`);
  });
  console.log();

  // Example 10: Export search results
  console.log('=== Example 10: Export Search Results ===');
  const exportResults = await searchManager.search('error', undefined, { limit: 5 });
  
  // Export as JSON
  const jsonExport = await searchManager.exportResults(exportResults, {
    format: 'json',
    includeMetadata: true,
    fields: ['timestamp', 'level', 'message', 'appName'],
  });
  console.log('Exported as JSON (truncated):');
  console.log(jsonExport.substring(0, 200) + '...');
  console.log();

  // Export as CSV
  const csvExport = await searchManager.exportResults(exportResults, {
    format: 'csv',
    fields: ['timestamp', 'level', 'appName', 'message'],
  });
  console.log('Exported as CSV:');
  console.log(csvExport.split('\n').slice(0, 4).join('\n'));
  console.log();

  // Example 11: Multi-criteria correlation
  console.log('=== Example 11: Multi-Criteria Correlation ===');
  const correlations = await searchManager.correlateByMultipleCriteria({
    traceId: true,
    temporal: true,
    errorCascade: true,
  });
  
  console.log(`Found ${correlations.size} correlation groups:`);
  let count = 0;
  for (const [key, corr] of correlations.entries()) {
    if (count++ >= 3) break;
    console.log(`  ${key}: ${corr.logs.length} logs`);
    console.log(`    Services: ${corr.summary?.services.join(', ')}`);
    console.log(`    Errors: ${corr.summary?.errorCount}`);
  }
  console.log();

  // Example 12: Find related logs
  console.log('=== Example 12: Find Related Logs ===');
  const sampleLog = sampleLogs[Math.floor(sampleLogs.length / 2)];
  const relatedLogs = await searchManager.findRelatedLogs(sampleLog, 5);
  
  console.log(`Finding logs related to: ${sampleLog.message}`);
  console.log(`Found ${relatedLogs.length} related logs:`);
  relatedLogs.forEach((related, i) => {
    console.log(`  ${i + 1}. Relationship: ${related.relationship}`);
    console.log(`     Score: ${related.score.toFixed(2)}`);
    console.log(`     ${related.log.message}`);
  });
  console.log();

  console.log('=== Demo Complete ===');
}

async function generateSampleLogs(logger: any): Promise<LogEntry[]> {
  const logs: LogEntry[] = [];
  const services = ['payment', 'auth', 'orders', 'inventory'];
  const traceIds = ['trace-123', 'trace-456', 'trace-789'];
  const userIds = ['user123', 'user456', 'user789'];

  // Generate diverse logs
  for (let i = 0; i < 100; i++) {
    const service = services[Math.floor(Math.random() * services.length)];
    const traceId = traceIds[Math.floor(Math.random() * traceIds.length)];
    const userId = userIds[Math.floor(Math.random() * userIds.length)];
    const timestamp = new Date(Date.now() - Math.random() * 3600000).toISOString();

    if (i % 10 === 0) {
      // Error log
      logs.push({
        timestamp,
        level: 'error',
        appName: service,
        traceId,
        message: `Database connection failed for ${service} service`,
        payload: { userId, errorCode: 'DB_CONN_ERR' },
      });
    } else if (i % 7 === 0) {
      // Warning log
      logs.push({
        timestamp,
        level: 'warn',
        appName: service,
        traceId,
        message: `Slow query detected in ${service}: took 1500ms`,
        payload: { userId, queryTime: 1500 },
      });
    } else {
      // Info log
      logs.push({
        timestamp,
        level: 'info',
        appName: service,
        traceId,
        message: `Request processed successfully by ${service}`,
        payload: { userId, responseTime: Math.floor(Math.random() * 500) },
      });
    }
  }

  // Add some correlated logs for trace-123
  const correlatedTrace = 'trace-123';
  logs.push({
    timestamp: new Date(Date.now() - 1000).toISOString(),
    level: 'info',
    appName: 'payment',
    traceId: correlatedTrace,
    message: 'Payment request started',
    payload: { userId: 'user123', amount: 99.99 },
  });
  
  logs.push({
    timestamp: new Date(Date.now() - 800).toISOString(),
    level: 'info',
    appName: 'payment',
    traceId: correlatedTrace,
    message: 'Validating payment method',
    payload: { userId: 'user123' },
  });
  
  logs.push({
    timestamp: new Date(Date.now() - 500).toISOString(),
    level: 'error',
    appName: 'payment',
    traceId: correlatedTrace,
    message: 'Payment gateway timeout',
    payload: { userId: 'user123', errorCode: 'GATEWAY_TIMEOUT' },
    error: new Error('Payment gateway timeout'),
  });
  
  logs.push({
    timestamp: new Date(Date.now() - 200).toISOString(),
    level: 'info',
    appName: 'payment',
    traceId: correlatedTrace,
    message: 'Payment request completed with error',
    payload: { userId: 'user123', success: false },
  });

  return logs;
}

// Run the demo
main().catch(console.error);
