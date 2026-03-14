/**
 * Search module exports
 *
 * Smart Log Aggregation and Intelligent Search System
 */

// Main search manager
export type { SearchManagerConfig } from './search-manager';
export { SearchManager } from './search-manager';

// Core interfaces and classes
export { BasicLogIndexer } from './core/basic-log-indexer';
export { BasicSearchEngine } from './core/basic-search-engine';
export type { ILogIndexer } from './core/log-indexer.interface';
export type { ILogSearchEngine } from './core/search-engine.interface';

// Advanced engines
export { CorrelationEngine } from './engines/correlation-engine';
export { NLPSearchEngine } from './engines/nlp-search-engine';
export { PatternRecognitionEngine } from './engines/pattern-recognition-engine';

// Types
export type * from './types';
