/**
 * Main search manager that orchestrates all search capabilities
 */

import { LogEntry } from '../types';
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
  LogPattern,
  AnomalyDetection,
  RelatedLog,
  ExportOptions,
} from './types';
import { BasicSearchEngine } from './core/basic-search-engine';
import { BasicLogIndexer } from './core/basic-log-indexer';
import { NLPSearchEngine } from './engines/nlp-search-engine';
import { PatternRecognitionEngine } from './engines/pattern-recognition-engine';
import { CorrelationEngine } from './engines/correlation-engine';

/**
 * Configuration for search manager
 */
export interface SearchManagerConfig {
  enableNLP?: boolean;
  enablePatternRecognition?: boolean;
  enableCorrelation?: boolean;
  maxIndexSize?: number;
  autoOptimize?: boolean;
}

/**
 * Main search manager class
 */
export class SearchManager {
  private searchEngine: BasicSearchEngine | NLPSearchEngine;
  private indexer: BasicLogIndexer;
  private patternEngine?: PatternRecognitionEngine;
  private correlationEngine?: CorrelationEngine;
  private config: Required<SearchManagerConfig>;

  constructor(config?: SearchManagerConfig) {
    this.config = {
      enableNLP: true,
      enablePatternRecognition: true,
      enableCorrelation: true,
      maxIndexSize: 1000000,
      autoOptimize: true,
      ...config,
    };

    // Initialize components
    this.searchEngine = this.config.enableNLP
      ? new NLPSearchEngine()
      : new BasicSearchEngine();

    this.indexer = new BasicLogIndexer({
      maxIndexSize: this.config.maxIndexSize,
      autoOptimize: this.config.autoOptimize,
    });

    if (this.config.enablePatternRecognition) {
      this.patternEngine = new PatternRecognitionEngine();
    }

    if (this.config.enableCorrelation) {
      this.correlationEngine = new CorrelationEngine();
    }
  }

  /**
   * Index new logs
   */
  async indexLogs(logs: LogEntry[]): Promise<void> {
    await this.indexer.indexBatch(logs);
    this.searchEngine.addLogs(logs);

    // Analyze patterns if enabled
    if (this.patternEngine && logs.length > 10) {
      await this.patternEngine.analyzePatterns(logs);
    }
  }

  /**
   * Add a single log to the index
   */
  async indexLog(log: LogEntry): Promise<void> {
    await this.indexer.indexLog(log);
    this.searchEngine.addLogs([log]);
  }

  /**
   * Perform a search
   */
  async search(
    query: string,
    filters?: SearchFilters,
    options?: SearchOptions
  ): Promise<SearchResult[]> {
    return this.searchEngine.search(query, filters, options);
  }

  /**
   * Perform a natural language search
   */
  async naturalLanguageSearch(query: string): Promise<SearchResult[]> {
    return this.searchEngine.naturalLanguageSearch(query);
  }

  /**
   * Find logs correlated by trace ID
   */
  async correlateByTraceId(traceId: string): Promise<CorrelatedLogs> {
    return this.searchEngine.correlateByTraceId(traceId);
  }

  /**
   * Find similar logs
   */
  async findSimilarLogs(logEntry: LogEntry, limit?: number): Promise<SimilarLog[]> {
    return this.searchEngine.findSimilarLogs(logEntry, limit);
  }

  /**
   * Find logs related to a given log
   */
  async findRelatedLogs(log: LogEntry, limit?: number): Promise<RelatedLog[]> {
    if (!this.correlationEngine) {
      throw new Error('Correlation engine not enabled');
    }

    const allLogs = this.searchEngine.getLogs();
    return this.correlationEngine.findRelatedLogs(log, allLogs, limit);
  }

  /**
   * Get search suggestions
   */
  async getSuggestions(partialQuery: string, limit?: number): Promise<SearchSuggestion[]> {
    return this.searchEngine.getSuggestions(partialQuery, limit);
  }

  /**
   * Get search statistics
   */
  async getStats(): Promise<SearchStats> {
    return this.searchEngine.getStats();
  }

  /**
   * Parse natural language query
   */
  async parseNaturalLanguageQuery(query: string): Promise<ParsedNLQuery> {
    return this.searchEngine.parseNaturalLanguageQuery(query);
  }

  /**
   * Save a search preset
   */
  async savePreset(
    preset: Omit<SearchPreset, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<SearchPreset> {
    return this.searchEngine.savePreset(preset);
  }

  /**
   * Get saved presets
   */
  async getPresets(userId?: string): Promise<SearchPreset[]> {
    return this.searchEngine.getPresets(userId);
  }

  /**
   * Delete a preset
   */
  async deletePreset(presetId: string): Promise<void> {
    return this.searchEngine.deletePreset(presetId);
  }

  /**
   * Detect log patterns
   */
  async detectPatterns(): Promise<LogPattern[]> {
    if (!this.patternEngine) {
      throw new Error('Pattern recognition not enabled');
    }

    const allLogs = this.searchEngine.getLogs();
    return this.patternEngine.analyzePatterns(allLogs);
  }

  /**
   * Get detected patterns
   */
  getPatterns(): LogPattern[] {
    if (!this.patternEngine) {
      return [];
    }

    return this.patternEngine.getPatterns();
  }

  /**
   * Detect anomalies in logs
   */
  async detectAnomalies(): Promise<AnomalyDetection[]> {
    if (!this.patternEngine) {
      throw new Error('Pattern recognition not enabled');
    }

    const allLogs = this.searchEngine.getLogs();
    return this.patternEngine.detectAnomalies(allLogs);
  }

  /**
   * Correlate logs by multiple criteria
   */
  async correlateByMultipleCriteria(criteria: {
    traceId?: boolean;
    userId?: boolean;
    sessionId?: boolean;
    temporal?: boolean;
    errorCascade?: boolean;
  }): Promise<Map<string, CorrelatedLogs>> {
    if (!this.correlationEngine) {
      throw new Error('Correlation engine not enabled');
    }

    const allLogs = this.searchEngine.getLogs();
    return this.correlationEngine.correlateByMultipleCriteria(allLogs, criteria);
  }

  /**
   * Analyze error cascades
   */
  async analyzeErrorCascade(traceId: string): Promise<{
    rootCause?: LogEntry;
    cascade: LogEntry[];
    impactedServices: string[];
  }> {
    if (!this.correlationEngine) {
      throw new Error('Correlation engine not enabled');
    }

    const correlated = await this.correlateByTraceId(traceId);
    return this.correlationEngine.analyzeErrorCascade(correlated.logs);
  }

  /**
   * Export search results
   */
  async exportResults(
    results: SearchResult[],
    options: ExportOptions
  ): Promise<string> {
    switch (options.format) {
      case 'json':
        return this.exportAsJSON(results, options);
      case 'csv':
        return this.exportAsCSV(results, options);
      case 'text':
        return this.exportAsText(results, options);
      default:
        throw new Error(`Unsupported export format: ${options.format}`);
    }
  }

  /**
   * Clear all indexed data
   */
  async clearIndex(): Promise<void> {
    await this.indexer.clearIndex();
    this.searchEngine.clearLogs();
  }

  /**
   * Optimize the index
   */
  async optimizeIndex(): Promise<void> {
    await this.indexer.optimizeIndex();
  }

  /**
   * Get index statistics
   */
  async getIndexStats(): Promise<{
    totalDocuments: number;
    indexSize: number;
    lastOptimized?: Date;
  }> {
    return this.indexer.getIndexStats();
  }

  /**
   * Remove old logs
   */
  async removeOldLogs(olderThan: Date): Promise<number> {
    const removed = await this.indexer.removeOldLogs(olderThan);
    
    // Also remove from search engine
    const allLogs = this.searchEngine.getLogs();
    const filteredLogs = allLogs.filter(
      (log) => new Date(log.timestamp) >= olderThan
    );
    
    this.searchEngine.clearLogs();
    this.searchEngine.addLogs(filteredLogs);
    
    return removed;
  }

  // Private export methods

  private exportAsJSON(results: SearchResult[], options: ExportOptions): string {
    const data = options.includeMetadata
      ? results
      : results.map((r) => r.log);

    if (options.fields) {
      return JSON.stringify(
        data.map((item) => this.filterFields(item, options.fields!)),
        null,
        2
      );
    }

    return JSON.stringify(data, null, 2);
  }

  private exportAsCSV(results: SearchResult[], options: ExportOptions): string {
    const logs = results.map((r) => r.log);
    
    if (logs.length === 0) {
      return '';
    }

    const fields = options.fields || ['timestamp', 'level', 'appName', 'message'];
    const headers = fields.join(',');
    
    const rows = logs.map((log) => {
      return fields
        .map((field) => {
          const value = (log as any)[field];
          return this.escapeCSVValue(value);
        })
        .join(',');
    });

    return [headers, ...rows].join('\n');
  }

  private exportAsText(results: SearchResult[], options: ExportOptions): string {
    return results
      .map((result) => {
        const log = result.log;
        let text = `[${log.timestamp}] [${log.level.toUpperCase()}] ${log.appName}: ${log.message}`;
        
        if (options.includeMetadata) {
          text += `\n  Score: ${result.score.toFixed(2)}`;
          if (result.highlights) {
            text += `\n  Matches: ${result.highlights.length}`;
          }
        }
        
        return text;
      })
      .join('\n\n');
  }

  private filterFields(obj: any, fields: string[]): any {
    const filtered: any = {};
    
    for (const field of fields) {
      if (field in obj) {
        filtered[field] = obj[field];
      } else if (field.includes('.')) {
        // Handle nested fields
        const value = this.getNestedValue(obj, field);
        if (value !== undefined) {
          filtered[field] = value;
        }
      }
    }
    
    return filtered;
  }

  private getNestedValue(obj: any, path: string): any {
    return path.split('.').reduce((current, key) => current?.[key], obj);
  }

  private escapeCSVValue(value: any): string {
    if (value === null || value === undefined) {
      return '';
    }

    const str = typeof value === 'object' ? JSON.stringify(value) : String(value);
    
    // Escape quotes and wrap in quotes if contains comma, newline, or quote
    if (str.includes(',') || str.includes('\n') || str.includes('"')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    
    return str;
  }
}
