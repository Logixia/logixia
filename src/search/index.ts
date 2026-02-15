/**
 * Search module exports
 * 
 * Smart Log Aggregation and Intelligent Search System
 */

// Main search manager
export { SearchManager } from './search-manager';
export type { SearchManagerConfig } from './search-manager';

// Core interfaces and classes
export type { ILogSearchEngine } from './core/search-engine.interface';
export type { ILogIndexer } from './core/log-indexer.interface';
export { BasicSearchEngine } from './core/basic-search-engine';
export { BasicLogIndexer } from './core/basic-log-indexer';

// Advanced engines
export { NLPSearchEngine } from './engines/nlp-search-engine';
export { PatternRecognitionEngine } from './engines/pattern-recognition-engine';
export { CorrelationEngine } from './engines/correlation-engine';

// Types
export type * from './types';
