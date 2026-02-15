/**
 * Log indexer interface for indexing and managing log entries
 */

import { LogEntry } from '../../types';
import { SemanticIndex, SearchQuery } from '../types';

/**
 * Log indexer interface
 */
export interface ILogIndexer {
  /**
   * Index a single log entry
   * @param log - Log entry to index
   */
  indexLog(log: LogEntry): Promise<void>;

  /**
   * Index multiple log entries in batch
   * @param logs - Array of log entries to index
   */
  indexBatch(logs: LogEntry[]): Promise<void>;

  /**
   * Build semantic index for intelligent search
   * @param logs - Array of log entries to build index from
   * @returns Semantic index
   */
  buildSemanticIndex(logs: LogEntry[]): Promise<SemanticIndex>;

  /**
   * Update search suggestions based on search history
   * @param searchHistory - Array of past search queries
   */
  updateSearchSuggestions(searchHistory: SearchQuery[]): Promise<void>;

  /**
   * Optimize the index for better performance
   */
  optimizeIndex(): Promise<void>;

  /**
   * Clear the index
   */
  clearIndex(): Promise<void>;

  /**
   * Get index statistics
   * @returns Index statistics
   */
  getIndexStats(): Promise<{
    totalDocuments: number;
    indexSize: number;
    lastOptimized?: Date;
  }>;

  /**
   * Remove logs older than specified time
   * @param olderThan - Remove logs older than this date
   * @returns Number of logs removed
   */
  removeOldLogs(olderThan: Date): Promise<number>;
}
