/**
 * Search engine interface for log search operations
 */

import {
  SearchResult,
  SearchFilters,
  SearchOptions,
  CorrelatedLogs,
  SimilarLog,
  SearchSuggestion,
  SearchStats,
  ParsedNLQuery,
  SearchPreset,
} from '../types';
import { LogEntry } from '../../types';

/**
 * Main search engine interface
 */
export interface ILogSearchEngine {
  /**
   * Perform a full-text search across logs
   * @param query - Search query string
   * @param filters - Optional filters to narrow down results
   * @param options - Search options
   * @returns Array of search results
   */
  search(
    query: string,
    filters?: SearchFilters,
    options?: SearchOptions
  ): Promise<SearchResult[]>;

  /**
   * Perform a natural language search
   * @param query - Natural language query
   * @returns Array of search results
   */
  naturalLanguageSearch(query: string): Promise<SearchResult[]>;

  /**
   * Find logs correlated by trace ID
   * @param traceId - Trace ID to correlate logs
   * @returns Correlated logs
   */
  correlateByTraceId(traceId: string): Promise<CorrelatedLogs>;

  /**
   * Find logs similar to a given log entry
   * @param logEntry - Log entry to find similar logs for
   * @param limit - Maximum number of similar logs to return
   * @returns Array of similar logs
   */
  findSimilarLogs(logEntry: LogEntry, limit?: number): Promise<SimilarLog[]>;

  /**
   * Get search suggestions based on partial query
   * @param partialQuery - Partial query string
   * @param limit - Maximum number of suggestions
   * @returns Array of suggestions
   */
  getSuggestions(partialQuery: string, limit?: number): Promise<SearchSuggestion[]>;

  /**
   * Get search statistics
   * @returns Search statistics
   */
  getStats(): Promise<SearchStats>;

  /**
   * Parse natural language query
   * @param query - Natural language query
   * @returns Parsed query with intent and entities
   */
  parseNaturalLanguageQuery(query: string): Promise<ParsedNLQuery>;

  /**
   * Save a search preset
   * @param preset - Search preset to save
   * @returns Saved preset with ID
   */
  savePreset(preset: Omit<SearchPreset, 'id' | 'createdAt' | 'updatedAt'>): Promise<SearchPreset>;

  /**
   * Get saved presets
   * @param userId - Optional user ID to filter presets
   * @returns Array of presets
   */
  getPresets(userId?: string): Promise<SearchPreset[]>;

  /**
   * Delete a preset
   * @param presetId - ID of preset to delete
   */
  deletePreset(presetId: string): Promise<void>;
}
