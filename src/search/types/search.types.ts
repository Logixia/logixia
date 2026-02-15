/**
 * Type definitions for intelligent log search system
 */

import { LogEntry } from '../../types';

/**
 * Search filter options
 */
export interface SearchFilters {
  levels?: string[];
  services?: string[];
  traceIds?: string[];
  timeRange?: TimeRange;
  userIds?: string[];
  sessionIds?: string[];
  contexts?: string[];
  excludePatterns?: string[];
  minSeverity?: number;
  hasError?: boolean;
  customFields?: Record<string, any>;
}

/**
 * Time range for filtering logs
 */
export interface TimeRange {
  start: Date | number;
  end?: Date | number;
  relative?: RelativeTime;
}

/**
 * Relative time specification
 */
export interface RelativeTime {
  value: number;
  unit: 'seconds' | 'minutes' | 'hours' | 'days';
}

/**
 * Search result with metadata
 */
export interface SearchResult {
  log: LogEntry;
  score: number;
  highlights?: SearchHighlight[];
  matches?: SearchMatch[];
  context?: LogEntry[];
  relatedLogs?: RelatedLog[];
}

/**
 * Search highlight information
 */
export interface SearchHighlight {
  field: string;
  fragments: string[];
  matchedTerms: string[];
}

/**
 * Search match details
 */
export interface SearchMatch {
  field: string;
  value: string;
  position: number;
  length: number;
}

/**
 * Related log entry
 */
export interface RelatedLog {
  log: LogEntry;
  relationship: RelationshipType;
  score: number;
}

/**
 * Type of relationship between logs
 */
export type RelationshipType = 
  | 'same_trace'
  | 'same_user'
  | 'same_session'
  | 'temporal_proximity'
  | 'error_cascade'
  | 'similar_pattern';

/**
 * Correlated logs grouped by trace ID or other criteria
 */
export interface CorrelatedLogs {
  traceId?: string;
  correlationKey: string;
  logs: LogEntry[];
  timeline: TimelineEvent[];
  summary?: LogCorrelationSummary;
}

/**
 * Timeline event for correlated logs
 */
export interface TimelineEvent {
  timestamp: Date;
  log: LogEntry;
  eventType: 'start' | 'end' | 'error' | 'milestone' | 'info';
  duration?: number;
}

/**
 * Summary of correlated logs
 */
export interface LogCorrelationSummary {
  totalLogs: number;
  errorCount: number;
  warningCount: number;
  duration?: number;
  services: string[];
  criticalPath?: LogEntry[];
}

/**
 * Similar log entry
 */
export interface SimilarLog {
  log: LogEntry;
  similarity: number;
  matchedPatterns: string[];
  reason: string;
}

/**
 * Search query with metadata
 */
export interface SearchQuery {
  query: string;
  filters?: SearchFilters;
  options?: SearchOptions;
  timestamp: Date;
  userId?: string;
}

/**
 * Search options
 */
export interface SearchOptions {
  limit?: number;
  offset?: number;
  sortBy?: SortField;
  sortOrder?: 'asc' | 'desc';
  includeContext?: boolean;
  contextSize?: number;
  highlightMatches?: boolean;
  findSimilar?: boolean;
  correlate?: boolean;
  semanticSearch?: boolean;
}

/**
 * Sort field options
 */
export type SortField = 'timestamp' | 'level' | 'score' | 'relevance';

/**
 * Search suggestion
 */
export interface SearchSuggestion {
  text: string;
  type: SuggestionType;
  category?: string;
  frequency?: number;
  lastUsed?: Date;
}

/**
 * Suggestion type
 */
export type SuggestionType = 
  | 'field'
  | 'value'
  | 'operator'
  | 'query_history'
  | 'pattern'
  | 'filter';

/**
 * Search statistics
 */
export interface SearchStats {
  totalResults: number;
  executionTime: number;
  indexSize: number;
  cacheHitRate?: number;
  topTerms?: string[];
}

/**
 * Semantic index for intelligent search
 */
export interface SemanticIndex {
  version: string;
  indexedCount: number;
  lastUpdated: Date;
  embeddings?: Map<string, number[]>;
  clusters?: LogCluster[];
}

/**
 * Log cluster for grouping similar logs
 */
export interface LogCluster {
  id: string;
  centroid: number[];
  logs: LogEntry[];
  pattern: string;
  frequency: number;
  labels?: string[];
}

/**
 * Log pattern for pattern recognition
 */
export interface LogPattern {
  id: string;
  pattern: string;
  regex?: RegExp;
  examples: LogEntry[];
  frequency: number;
  lastSeen: Date;
  category?: string;
  severity?: string;
}

/**
 * Anomaly detection result
 */
export interface AnomalyDetection {
  log: LogEntry;
  anomalyScore: number;
  reason: string;
  expectedPattern?: string;
  deviations: string[];
}

/**
 * Natural language query parsed result
 */
export interface ParsedNLQuery {
  originalQuery: string;
  intent: QueryIntent;
  entities: QueryEntity[];
  filters: SearchFilters;
  timeRange?: TimeRange;
  confidence: number;
}

/**
 * Query intent
 */
export type QueryIntent = 
  | 'find_errors'
  | 'trace_request'
  | 'find_user_activity'
  | 'performance_analysis'
  | 'find_similar'
  | 'time_range_query'
  | 'correlation'
  | 'general_search';

/**
 * Query entity extracted from natural language
 */
export interface QueryEntity {
  type: EntityType;
  value: string;
  field?: string;
  confidence: number;
}

/**
 * Entity type
 */
export type EntityType = 
  | 'level'
  | 'service'
  | 'user_id'
  | 'trace_id'
  | 'time'
  | 'error_type'
  | 'field_value';

/**
 * Search preset for saving common searches
 */
export interface SearchPreset {
  id: string;
  name: string;
  description?: string;
  query: string;
  filters: SearchFilters;
  options: SearchOptions;
  createdAt: Date;
  updatedAt: Date;
  userId?: string;
  shared?: boolean;
}

/**
 * Export options for search results
 */
export interface ExportOptions {
  format: 'json' | 'csv' | 'text';
  includeMetadata?: boolean;
  filename?: string;
  fields?: string[];
}
