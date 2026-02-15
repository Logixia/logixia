/**
 * Basic search engine implementation with full-text search and filtering
 */

import { LogEntry } from '../../types';
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
  SearchHighlight,
  TimelineEvent,
  LogCorrelationSummary,
} from '../types';
import { ILogSearchEngine } from './search-engine.interface';

/**
 * Basic search engine implementation
 */
export class BasicSearchEngine implements ILogSearchEngine {
  private logs: LogEntry[] = [];
  private presets: Map<string, SearchPreset> = new Map();
  private searchHistory: string[] = [];
  private suggestionCache: Map<string, SearchSuggestion[]> = new Map();

  constructor(private options?: { maxHistorySize?: number; cacheSize?: number }) {
    this.options = {
      maxHistorySize: 1000,
      cacheSize: 100,
      ...options,
    };
  }

  /**
   * Add logs to the search index
   */
  public addLogs(logs: LogEntry[]): void {
    this.logs.push(...logs);
  }

  /**
   * Clear all logs from the index
   */
  public clearLogs(): void {
    this.logs = [];
  }

  /**
   * Get all indexed logs
   */
  public getLogs(): LogEntry[] {
    return this.logs;
  }

  /**
   * Perform a full-text search across logs
   */
  async search(
    query: string,
    filters?: SearchFilters,
    options?: SearchOptions
  ): Promise<SearchResult[]> {
    const startTime = Date.now();

    // Apply filters first
    let filteredLogs = this.applyFilters(this.logs, filters);

    // Perform text search
    const results = this.performTextSearch(filteredLogs, query, options);

    // Add to search history
    this.addToSearchHistory(query);

    // Apply sorting
    const sorted = this.applySorting(results, options?.sortBy, options?.sortOrder);

    // Apply pagination
    const paginated = this.applyPagination(sorted, options?.offset, options?.limit);

    // Add context if requested
    if (options?.includeContext) {
      await this.enrichWithContext(paginated, options.contextSize);
    }

    return paginated;
  }

  /**
   * Natural language search (basic implementation)
   */
  async naturalLanguageSearch(query: string): Promise<SearchResult[]> {
    const parsed = await this.parseNaturalLanguageQuery(query);
    return this.search(parsed.originalQuery, parsed.filters, {
      semanticSearch: true,
      includeContext: true,
    });
  }

  /**
   * Find logs correlated by trace ID
   */
  async correlateByTraceId(traceId: string): Promise<CorrelatedLogs> {
    const correlatedLogs = this.logs.filter((log) => log.traceId === traceId);

    // Sort by timestamp
    correlatedLogs.sort((a, b) => 
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    // Build timeline
    const timeline: TimelineEvent[] = correlatedLogs.map((log) => {
      let eventType: TimelineEvent['eventType'] = 'info';
      
      if (log.level === 'error') eventType = 'error';
      else if (log.message.toLowerCase().includes('start')) eventType = 'start';
      else if (log.message.toLowerCase().includes('end') || log.message.toLowerCase().includes('complete')) eventType = 'end';
      else if (log.message.toLowerCase().includes('milestone')) eventType = 'milestone';

      return {
        timestamp: new Date(log.timestamp),
        log,
        eventType,
      };
    });

    // Generate summary
    const summary: LogCorrelationSummary = {
      totalLogs: correlatedLogs.length,
      errorCount: correlatedLogs.filter((l) => l.level === 'error').length,
      warningCount: correlatedLogs.filter((l) => l.level === 'warn').length,
      services: [...new Set(correlatedLogs.map((l) => l.appName))],
    };

    // Calculate duration if we have start and end
    if (timeline.length > 0) {
      const start = timeline[0].timestamp.getTime();
      const end = timeline[timeline.length - 1].timestamp.getTime();
      summary.duration = end - start;
    }

    return {
      traceId,
      correlationKey: traceId,
      logs: correlatedLogs,
      timeline,
      summary,
    };
  }

  /**
   * Find similar logs based on content similarity
   */
  async findSimilarLogs(logEntry: LogEntry, limit: number = 10): Promise<SimilarLog[]> {
    const similarities: SimilarLog[] = [];

    for (const log of this.logs) {
      if (log === logEntry) continue;

      const similarity = this.calculateSimilarity(logEntry, log);
      if (similarity > 0.3) {
        // Threshold for similarity
        similarities.push({
          log,
          similarity,
          matchedPatterns: this.findMatchedPatterns(logEntry, log),
          reason: this.generateSimilarityReason(logEntry, log, similarity),
        });
      }
    }

    // Sort by similarity and return top results
    return similarities
      .sort((a, b) => b.similarity - a.similarity)
      .slice(0, limit);
  }

  /**
   * Get search suggestions
   */
  async getSuggestions(
    partialQuery: string,
    limit: number = 10
  ): Promise<SearchSuggestion[]> {
    const cacheKey = partialQuery.toLowerCase();
    
    // Check cache
    if (this.suggestionCache.has(cacheKey)) {
      return this.suggestionCache.get(cacheKey)!.slice(0, limit);
    }

    const suggestions: SearchSuggestion[] = [];

    // Field suggestions
    const fields = ['level', 'appName', 'traceId', 'message', 'timestamp'];
    for (const field of fields) {
      if (field.toLowerCase().includes(partialQuery.toLowerCase())) {
        suggestions.push({
          text: field,
          type: 'field',
          category: 'field',
        });
      }
    }

    // Value suggestions from logs
    const values = new Set<string>();
    for (const log of this.logs.slice(-1000)) {
      // Recent logs only
      if (log.level?.toLowerCase().includes(partialQuery.toLowerCase())) {
        values.add(log.level);
      }
      if (log.appName?.toLowerCase().includes(partialQuery.toLowerCase())) {
        values.add(log.appName);
      }
    }

    for (const value of values) {
      suggestions.push({
        text: value,
        type: 'value',
        category: 'value',
      });
    }

    // History suggestions
    for (const historyItem of this.searchHistory.slice(-50)) {
      if (historyItem.toLowerCase().includes(partialQuery.toLowerCase())) {
        suggestions.push({
          text: historyItem,
          type: 'query_history',
          category: 'history',
        });
      }
    }

    // Cache suggestions
    this.suggestionCache.set(cacheKey, suggestions);

    // Trim cache if too large
    if (this.suggestionCache.size > (this.options?.cacheSize || 100)) {
      const firstKey = this.suggestionCache.keys().next().value;
      this.suggestionCache.delete(firstKey);
    }

    return suggestions.slice(0, limit);
  }

  /**
   * Get search statistics
   */
  async getStats(): Promise<SearchStats> {
    return {
      totalResults: this.logs.length,
      executionTime: 0,
      indexSize: this.logs.length,
      topTerms: this.getTopTerms(),
    };
  }

  /**
   * Parse natural language query
   */
  async parseNaturalLanguageQuery(query: string): Promise<ParsedNLQuery> {
    const filters: SearchFilters = {};
    const lowerQuery = query.toLowerCase();

    // Extract levels
    const levels: string[] = [];
    if (lowerQuery.includes('error')) levels.push('error');
    if (lowerQuery.includes('warn')) levels.push('warn');
    if (lowerQuery.includes('info')) levels.push('info');
    if (levels.length > 0) filters.levels = levels;

    // Extract time range
    const timeRange = this.extractTimeRange(query);
    if (timeRange) filters.timeRange = timeRange;

    // Extract service names (basic pattern matching)
    const serviceMatch = query.match(/from\s+(?:the\s+)?(\w+)\s+service/i);
    if (serviceMatch) {
      filters.services = [serviceMatch[1]];
    }

    // Extract user ID
    const userMatch = query.match(/user\s+(?:id\s+)?(\w+)/i);
    if (userMatch) {
      filters.userIds = [userMatch[1]];
    }

    // Determine intent
    let intent: ParsedNLQuery['intent'] = 'general_search';
    if (lowerQuery.includes('error')) intent = 'find_errors';
    if (lowerQuery.includes('trace') || lowerQuery.includes('request')) intent = 'trace_request';
    if (lowerQuery.includes('user')) intent = 'find_user_activity';
    if (lowerQuery.includes('slow') || lowerQuery.includes('performance')) intent = 'performance_analysis';

    return {
      originalQuery: query,
      intent,
      entities: [],
      filters,
      confidence: 0.7,
    };
  }

  /**
   * Save a search preset
   */
  async savePreset(
    preset: Omit<SearchPreset, 'id' | 'createdAt' | 'updatedAt'>
  ): Promise<SearchPreset> {
    const id = this.generateId();
    const now = new Date();
    
    const fullPreset: SearchPreset = {
      ...preset,
      id,
      createdAt: now,
      updatedAt: now,
    };

    this.presets.set(id, fullPreset);
    return fullPreset;
  }

  /**
   * Get saved presets
   */
  async getPresets(userId?: string): Promise<SearchPreset[]> {
    const allPresets = Array.from(this.presets.values());
    
    if (userId) {
      return allPresets.filter((p) => p.userId === userId || p.shared);
    }
    
    return allPresets;
  }

  /**
   * Delete a preset
   */
  async deletePreset(presetId: string): Promise<void> {
    this.presets.delete(presetId);
  }

  // Private helper methods

  private applyFilters(logs: LogEntry[], filters?: SearchFilters): LogEntry[] {
    if (!filters) return logs;

    return logs.filter((log) => {
      // Level filter
      if (filters.levels && !filters.levels.includes(log.level)) {
        return false;
      }

      // Service filter
      if (filters.services && !filters.services.includes(log.appName)) {
        return false;
      }

      // Trace ID filter
      if (filters.traceIds && log.traceId && !filters.traceIds.includes(log.traceId)) {
        return false;
      }

      // Time range filter
      if (filters.timeRange) {
        const logTime = new Date(log.timestamp).getTime();
        const start = typeof filters.timeRange.start === 'number' 
          ? filters.timeRange.start 
          : filters.timeRange.start.getTime();
        
        if (logTime < start) return false;
        
        if (filters.timeRange.end) {
          const end = typeof filters.timeRange.end === 'number'
            ? filters.timeRange.end
            : filters.timeRange.end.getTime();
          if (logTime > end) return false;
        }
      }

      // Error filter
      if (filters.hasError !== undefined) {
        const hasError = log.level === 'error' || !!log.error;
        if (filters.hasError !== hasError) return false;
      }

      // Context filter
      if (filters.contexts && log.context && !filters.contexts.includes(log.context)) {
        return false;
      }

      return true;
    });
  }

  private performTextSearch(
    logs: LogEntry[],
    query: string,
    options?: SearchOptions
  ): SearchResult[] {
    if (!query) {
      return logs.map((log) => ({ log, score: 1 }));
    }

    const queryTerms = query.toLowerCase().split(/\s+/);
    const results: SearchResult[] = [];

    for (const log of logs) {
      const searchableText = this.getSearchableText(log).toLowerCase();
      let score = 0;
      const highlights: SearchHighlight[] = [];
      const matchedTerms: string[] = [];

      for (const term of queryTerms) {
        if (searchableText.includes(term)) {
          score += 1;
          matchedTerms.push(term);
        }
      }

      if (score > 0) {
        // Add highlights if requested
        if (options?.highlightMatches) {
          highlights.push({
            field: 'message',
            fragments: this.getHighlightFragments(log.message, matchedTerms),
            matchedTerms,
          });
        }

        results.push({
          log,
          score: score / queryTerms.length, // Normalize score
          highlights: highlights.length > 0 ? highlights : undefined,
        });
      }
    }

    return results;
  }

  private getSearchableText(log: LogEntry): string {
    return [
      log.message,
      log.level,
      log.appName,
      log.context,
      JSON.stringify(log.payload),
    ]
      .filter(Boolean)
      .join(' ');
  }

  private getHighlightFragments(text: string, terms: string[]): string[] {
    const fragments: string[] = [];
    const lowerText = text.toLowerCase();

    for (const term of terms) {
      const index = lowerText.indexOf(term);
      if (index !== -1) {
        const start = Math.max(0, index - 30);
        const end = Math.min(text.length, index + term.length + 30);
        fragments.push(text.substring(start, end));
      }
    }

    return fragments;
  }

  private applySorting(
    results: SearchResult[],
    sortBy?: string,
    sortOrder: 'asc' | 'desc' = 'desc'
  ): SearchResult[] {
    const sorted = [...results];

    sorted.sort((a, b) => {
      let comparison = 0;

      switch (sortBy) {
        case 'timestamp':
          comparison = new Date(a.log.timestamp).getTime() - new Date(b.log.timestamp).getTime();
          break;
        case 'level':
          comparison = a.log.level.localeCompare(b.log.level);
          break;
        case 'score':
        case 'relevance':
        default:
          comparison = a.score - b.score;
          break;
      }

      return sortOrder === 'asc' ? comparison : -comparison;
    });

    return sorted;
  }

  private applyPagination(
    results: SearchResult[],
    offset: number = 0,
    limit: number = 100
  ): SearchResult[] {
    return results.slice(offset, offset + limit);
  }

  private async enrichWithContext(
    results: SearchResult[],
    contextSize: number = 5
  ): Promise<void> {
    for (const result of results) {
      const logIndex = this.logs.indexOf(result.log);
      if (logIndex !== -1) {
        const start = Math.max(0, logIndex - contextSize);
        const end = Math.min(this.logs.length, logIndex + contextSize + 1);
        result.context = this.logs.slice(start, end).filter((l) => l !== result.log);
      }
    }
  }

  private calculateSimilarity(log1: LogEntry, log2: LogEntry): number {
    let score = 0;
    let factors = 0;

    // Same level
    if (log1.level === log2.level) {
      score += 0.3;
    }
    factors++;

    // Same service
    if (log1.appName === log2.appName) {
      score += 0.2;
    }
    factors++;

    // Same trace
    if (log1.traceId && log1.traceId === log2.traceId) {
      score += 0.3;
    }
    factors++;

    // Message similarity
    const messageSimilarity = this.calculateTextSimilarity(log1.message, log2.message);
    score += messageSimilarity * 0.2;
    factors++;

    return score / factors;
  }

  private calculateTextSimilarity(text1: string, text2: string): number {
    const words1 = new Set(text1.toLowerCase().split(/\s+/));
    const words2 = new Set(text2.toLowerCase().split(/\s+/));
    
    const intersection = new Set([...words1].filter((x) => words2.has(x)));
    const union = new Set([...words1, ...words2]);
    
    return union.size > 0 ? intersection.size / union.size : 0;
  }

  private findMatchedPatterns(log1: LogEntry, log2: LogEntry): string[] {
    const patterns: string[] = [];

    if (log1.level === log2.level) patterns.push('same_level');
    if (log1.appName === log2.appName) patterns.push('same_service');
    if (log1.traceId === log2.traceId) patterns.push('same_trace');
    if (log1.context === log2.context) patterns.push('same_context');

    return patterns;
  }

  private generateSimilarityReason(log1: LogEntry, log2: LogEntry, similarity: number): string {
    const reasons: string[] = [];

    if (log1.level === log2.level) reasons.push('same log level');
    if (log1.appName === log2.appName) reasons.push('same service');
    if (log1.traceId === log2.traceId) reasons.push('same trace ID');

    return reasons.length > 0
      ? `Similar because: ${reasons.join(', ')}`
      : `${Math.round(similarity * 100)}% content similarity`;
  }

  private extractTimeRange(query: string): any {
    const lowerQuery = query.toLowerCase();

    // Last hour
    if (lowerQuery.includes('last hour') || lowerQuery.includes('past hour')) {
      return {
        start: new Date(Date.now() - 60 * 60 * 1000),
      };
    }

    // Last N hours
    const hoursMatch = query.match(/last\s+(\d+)\s+hours?/i);
    if (hoursMatch) {
      return {
        start: new Date(Date.now() - parseInt(hoursMatch[1]) * 60 * 60 * 1000),
      };
    }

    // Today
    if (lowerQuery.includes('today')) {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      return {
        start: today,
      };
    }

    return undefined;
  }

  private addToSearchHistory(query: string): void {
    this.searchHistory.push(query);
    
    // Trim history if too large
    const maxSize = this.options?.maxHistorySize || 1000;
    if (this.searchHistory.length > maxSize) {
      this.searchHistory = this.searchHistory.slice(-maxSize);
    }
  }

  private getTopTerms(): string[] {
    const termCounts = new Map<string, number>();

    for (const log of this.logs.slice(-1000)) {
      const words = log.message.toLowerCase().split(/\s+/);
      for (const word of words) {
        if (word.length > 3) {
          // Ignore short words
          termCounts.set(word, (termCounts.get(word) || 0) + 1);
        }
      }
    }

    return Array.from(termCounts.entries())
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10)
      .map(([term]) => term);
  }

  private generateId(): string {
    return `preset_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}
