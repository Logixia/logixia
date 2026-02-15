/**
 * Basic log indexer implementation for indexing and managing log entries
 */

import { LogEntry } from '../../types';
import { SemanticIndex, SearchQuery, LogCluster } from '../types';
import { ILogIndexer } from './log-indexer.interface';

/**
 * Basic log indexer implementation
 */
export class BasicLogIndexer implements ILogIndexer {
  private index: Map<string, LogEntry> = new Map();
  private fieldIndices: Map<string, Map<string, Set<string>>> = new Map();
  private semanticIndex?: SemanticIndex;
  private lastOptimized?: Date;

  constructor(private options?: {
    maxIndexSize?: number;
    autoOptimize?: boolean;
    optimizeThreshold?: number;
  }) {
    this.options = {
      maxIndexSize: 1000000,
      autoOptimize: true,
      optimizeThreshold: 10000,
      ...options,
    };

    // Initialize field indices
    this.initializeFieldIndices();
  }

  /**
   * Index a single log entry
   */
  async indexLog(log: LogEntry): Promise<void> {
    const logId = this.generateLogId(log);
    
    // Add to main index
    this.index.set(logId, log);

    // Update field indices
    this.updateFieldIndices(logId, log);

    // Auto-optimize if threshold reached
    if (
      this.options?.autoOptimize &&
      this.index.size % (this.options.optimizeThreshold || 10000) === 0
    ) {
      await this.optimizeIndex();
    }

    // Enforce max size
    if (this.index.size > (this.options?.maxIndexSize || 1000000)) {
      await this.removeOldestLogs(Math.floor((this.options?.maxIndexSize || 1000000) * 0.1));
    }
  }

  /**
   * Index multiple log entries in batch
   */
  async indexBatch(logs: LogEntry[]): Promise<void> {
    for (const log of logs) {
      const logId = this.generateLogId(log);
      this.index.set(logId, log);
      this.updateFieldIndices(logId, log);
    }

    // Optimize after batch
    if (this.options?.autoOptimize) {
      await this.optimizeIndex();
    }
  }

  /**
   * Build semantic index for intelligent search
   */
  async buildSemanticIndex(logs: LogEntry[]): Promise<SemanticIndex> {
    // Build clusters based on log patterns
    const clusters = await this.clusterLogs(logs);

    this.semanticIndex = {
      version: '1.0.0',
      indexedCount: logs.length,
      lastUpdated: new Date(),
      clusters,
    };

    return this.semanticIndex;
  }

  /**
   * Update search suggestions based on search history
   */
  async updateSearchSuggestions(searchHistory: SearchQuery[]): Promise<void> {
    // Extract common patterns from search history
    const patterns = new Map<string, number>();

    for (const query of searchHistory) {
      const normalizedQuery = query.query.toLowerCase().trim();
      patterns.set(normalizedQuery, (patterns.get(normalizedQuery) || 0) + 1);
    }

    // Store top patterns (this could be expanded to a more sophisticated system)
    const topPatterns = Array.from(patterns.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 100);

    // In a real implementation, this would persist to storage
  }

  /**
   * Optimize the index for better performance
   */
  async optimizeIndex(): Promise<void> {
    // Rebuild field indices
    this.fieldIndices.clear();
    this.initializeFieldIndices();

    for (const [logId, log] of this.index.entries()) {
      this.updateFieldIndices(logId, log);
    }

    this.lastOptimized = new Date();
  }

  /**
   * Clear the index
   */
  async clearIndex(): Promise<void> {
    this.index.clear();
    this.fieldIndices.clear();
    this.semanticIndex = undefined;
    this.initializeFieldIndices();
  }

  /**
   * Get index statistics
   */
  async getIndexStats(): Promise<{
    totalDocuments: number;
    indexSize: number;
    lastOptimized?: Date;
  }> {
    return {
      totalDocuments: this.index.size,
      indexSize: this.calculateIndexSize(),
      lastOptimized: this.lastOptimized,
    };
  }

  /**
   * Remove logs older than specified time
   */
  async removeOldLogs(olderThan: Date): Promise<number> {
    const cutoffTime = olderThan.getTime();
    let removedCount = 0;

    for (const [logId, log] of this.index.entries()) {
      const logTime = new Date(log.timestamp).getTime();
      if (logTime < cutoffTime) {
        this.index.delete(logId);
        this.removeFromFieldIndices(logId);
        removedCount++;
      }
    }

    return removedCount;
  }

  /**
   * Search logs by field
   */
  public searchByField(field: string, value: string): LogEntry[] {
    const fieldIndex = this.fieldIndices.get(field);
    if (!fieldIndex) return [];

    const logIds = fieldIndex.get(value.toLowerCase());
    if (!logIds) return [];

    return Array.from(logIds)
      .map((id) => this.index.get(id))
      .filter((log): log is LogEntry => log !== undefined);
  }

  /**
   * Get all indexed logs
   */
  public getAllLogs(): LogEntry[] {
    return Array.from(this.index.values());
  }

  // Private helper methods

  private initializeFieldIndices(): void {
    const fields = ['level', 'appName', 'traceId', 'context', 'environment'];
    for (const field of fields) {
      this.fieldIndices.set(field, new Map());
    }
  }

  private updateFieldIndices(logId: string, log: LogEntry): void {
    // Index level
    this.addToFieldIndex('level', log.level, logId);

    // Index appName
    if (log.appName) {
      this.addToFieldIndex('appName', log.appName, logId);
    }

    // Index traceId
    if (log.traceId) {
      this.addToFieldIndex('traceId', log.traceId, logId);
    }

    // Index context
    if (log.context) {
      this.addToFieldIndex('context', log.context, logId);
    }

    // Index environment
    if (log.environment) {
      this.addToFieldIndex('environment', log.environment, logId);
    }
  }

  private addToFieldIndex(field: string, value: string, logId: string): void {
    const fieldIndex = this.fieldIndices.get(field);
    if (!fieldIndex) return;

    const normalizedValue = value.toLowerCase();
    if (!fieldIndex.has(normalizedValue)) {
      fieldIndex.set(normalizedValue, new Set());
    }
    fieldIndex.get(normalizedValue)!.add(logId);
  }

  private removeFromFieldIndices(logId: string): void {
    for (const fieldIndex of this.fieldIndices.values()) {
      for (const logIds of fieldIndex.values()) {
        logIds.delete(logId);
      }
    }
  }

  private generateLogId(log: LogEntry): string {
    return `${log.timestamp}_${log.level}_${Math.random().toString(36).substr(2, 9)}`;
  }

  private calculateIndexSize(): number {
    // Rough estimate of index size in bytes
    let size = 0;
    
    for (const log of this.index.values()) {
      size += JSON.stringify(log).length;
    }
    
    return size;
  }

  private async removeOldestLogs(count: number): Promise<void> {
    const logs = Array.from(this.index.entries())
      .sort((a, b) => 
        new Date(a[1].timestamp).getTime() - new Date(b[1].timestamp).getTime()
      )
      .slice(0, count);

    for (const [logId] of logs) {
      this.index.delete(logId);
      this.removeFromFieldIndices(logId);
    }
  }

  private async clusterLogs(logs: LogEntry[]): Promise<LogCluster[]> {
    // Simple clustering based on log patterns
    const clusters = new Map<string, LogEntry[]>();

    for (const log of logs) {
      // Create a pattern key based on level and service
      const patternKey = `${log.level}_${log.appName}`;
      
      if (!clusters.has(patternKey)) {
        clusters.set(patternKey, []);
      }
      clusters.get(patternKey)!.push(log);
    }

    // Convert to LogCluster format
    return Array.from(clusters.entries()).map(([pattern, clusterLogs], index) => ({
      id: `cluster_${index}`,
      centroid: [], // Would be calculated in a real implementation
      logs: clusterLogs,
      pattern,
      frequency: clusterLogs.length,
      labels: [pattern],
    }));
  }
}
