/**
 * Quick Start: Intelligent Log Search
 * 
 * Simple examples to get started with log search
 */

import { createLogger } from '../src';
import { SearchManager } from '../src/search';
import { LogEntry } from '../src/types';

async function quickStart() {
  // Initialize search manager
  const searchManager = new SearchManager({
    enableNLP: true,
    enablePatternRecognition: true,
    enableCorrelation: true,
  });

  // Sample logs for demonstration
  const sampleLogs: LogEntry[] = [
    {
      timestamp: new Date().toISOString(),
      level: 'error',
      appName: 'api-gateway',
      traceId: 'req-001',
      message: 'Database connection timeout',
      payload: { userId: 'user123', database: 'postgres' },
    },
    {
      timestamp: new Date().toISOString(),
      level: 'warn',
      appName: 'api-gateway',
      traceId: 'req-001',
      message: 'Retrying database connection',
      payload: { userId: 'user123', attempt: 2 },
    },
    {
      timestamp: new Date().toISOString(),
      level: 'info',
      appName: 'user-service',
      traceId: 'req-002',
      message: 'User login successful',
      payload: { userId: 'user456', ip: '192.168.1.1' },
    },
    {
      timestamp: new Date().toISOString(),
      level: 'error',
      appName: 'payment-service',
      traceId: 'req-003',
      message: 'Payment processing failed',
      payload: { userId: 'user789', amount: 99.99 },
    },
  ];

  // Index the logs
  await searchManager.indexLogs(sampleLogs);

  console.log('=== Quick Start Examples ===\n');

  // 1. Simple search
  console.log('1. Simple text search for "error":');
  const results = await searchManager.search('error');
  results.forEach((r, i) => {
    console.log(`   ${i + 1}. ${r.log.message}`);
  });
  console.log();

  // 2. Natural language search
  console.log('2. Natural language search:');
  const nlResults = await searchManager.naturalLanguageSearch(
    'Show me all errors from the api-gateway'
  );
  console.log(`   Found ${nlResults.length} results`);
  nlResults.forEach((r, i) => {
    console.log(`   ${i + 1}. ${r.log.message}`);
  });
  console.log();

  // 3. Filter by level
  console.log('3. Filter by log level:');
  const errorResults = await searchManager.search('', {
    levels: ['error'],
  });
  console.log(`   Found ${errorResults.length} errors`);
  console.log();

  // 4. Correlate by trace ID
  console.log('4. Correlate logs by trace ID:');
  const correlated = await searchManager.correlateByTraceId('req-001');
  console.log(`   Trace: ${correlated.traceId}`);
  console.log(`   Total logs: ${correlated.logs.length}`);
  console.log(`   Timeline:`);
  correlated.timeline.forEach((event, i) => {
    console.log(`     ${i + 1}. [${event.eventType}] ${event.log.message}`);
  });
  console.log();

  // 5. Find similar logs
  console.log('5. Find similar logs:');
  const referenceLog = sampleLogs[0];
  const similar = await searchManager.findSimilarLogs(referenceLog, 3);
  console.log(`   Reference: ${referenceLog.message}`);
  console.log(`   Similar logs:`);
  similar.forEach((s, i) => {
    console.log(`     ${i + 1}. [${s.similarity.toFixed(2)}] ${s.log.message}`);
  });
  console.log();

  // 6. Get search suggestions
  console.log('6. Search suggestions for "err":');
  const suggestions = await searchManager.getSuggestions('err', 5);
  suggestions.forEach((s, i) => {
    console.log(`   ${i + 1}. ${s.text} (${s.type})`);
  });
  console.log();

  // 7. Export results
  console.log('7. Export results as JSON:');
  const exportResults = await searchManager.search('error', undefined, { limit: 2 });
  const json = await searchManager.exportResults(exportResults, {
    format: 'json',
    fields: ['timestamp', 'level', 'message'],
  });
  console.log(json);
  console.log();

  console.log('=== Quick Start Complete ===');
}

quickStart().catch(console.error);
