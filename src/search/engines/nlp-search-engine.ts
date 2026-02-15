/**
 * Advanced search engine with Natural Language Processing capabilities
 */

import { LogEntry } from '../../types';
import {
  SearchResult,
  SearchFilters,
  SearchOptions,
  ParsedNLQuery,
  QueryIntent,
  QueryEntity,
  EntityType,
  TimeRange,
} from '../types';
import { BasicSearchEngine } from '../core/basic-search-engine';

/**
 * NLP-enhanced search engine
 */
export class NLPSearchEngine extends BasicSearchEngine {
  private intentPatterns: Map<QueryIntent, RegExp[]>;
  private entityPatterns: Map<EntityType, RegExp>;

  constructor(options?: any) {
    super(options);
    this.initializePatterns();
  }

  /**
   * Enhanced natural language query parsing
   */
  async parseNaturalLanguageQuery(query: string): Promise<ParsedNLQuery> {
    const lowerQuery = query.toLowerCase();
    const entities: QueryEntity[] = [];
    const filters: SearchFilters = {};

    // Detect intent
    const intent = this.detectIntent(query);

    // Extract entities
    const extractedEntities = this.extractEntities(query);
    entities.push(...extractedEntities);

    // Build filters from entities
    for (const entity of entities) {
      this.applyEntityToFilter(entity, filters);
    }

    // Extract time range
    const timeRange = this.extractAdvancedTimeRange(query);
    if (timeRange) {
      filters.timeRange = timeRange;
    }

    // Calculate confidence
    const confidence = this.calculateConfidence(intent, entities, query);

    return {
      originalQuery: query,
      intent,
      entities,
      filters,
      timeRange,
      confidence,
    };
  }

  /**
   * Enhanced natural language search
   */
  async naturalLanguageSearch(query: string): Promise<SearchResult[]> {
    const parsed = await this.parseNaturalLanguageQuery(query);

    // Adjust search options based on intent
    const options: SearchOptions = this.getOptionsForIntent(parsed.intent);

    // Extract clean search query (remove filter terms)
    const cleanQuery = this.extractCleanQuery(query, parsed.entities);

    return this.search(cleanQuery, parsed.filters, options);
  }

  // Private methods

  private initializePatterns(): void {
    // Initialize intent patterns
    this.intentPatterns = new Map([
      [
        'find_errors',
        [
          /show.*errors?/i,
          /find.*errors?/i,
          /all.*errors?/i,
          /errors?\s+(?:in|from|for)/i,
          /what.*went wrong/i,
          /failures?/i,
        ],
      ],
      [
        'trace_request',
        [
          /trace\s+(?:request|id)/i,
          /follow\s+request/i,
          /track\s+request/i,
          /request\s+(?:flow|path)/i,
          /trace.*across/i,
        ],
      ],
      [
        'find_user_activity',
        [
          /user\s+(?:\w+|id)/i,
          /activity\s+(?:for|of)\s+user/i,
          /what\s+did\s+user/i,
          /user\s+journey/i,
          /user\s+session/i,
        ],
      ],
      [
        'performance_analysis',
        [
          /slow\s+(?:queries?|requests?|operations?)/i,
          /performance\s+issues?/i,
          /latency/i,
          /response\s+time/i,
          /took\s+(?:too\s+)?long/i,
        ],
      ],
      [
        'time_range_query',
        [
          /(?:in|during|from)\s+the\s+last/i,
          /(?:today|yesterday|this\s+week)/i,
          /between.*and/i,
          /in\s+the\s+past/i,
        ],
      ],
      [
        'correlation',
        [
          /related\s+to/i,
          /connected\s+with/i,
          /caused\s+by/i,
          /before.*happened/i,
          /after.*occurred/i,
        ],
      ],
    ]);

    // Initialize entity patterns
    this.entityPatterns = new Map([
      ['level', /(error|warn|warning|info|debug|trace|verbose)/i],
      ['service', /(?:from|in)\s+(?:the\s+)?(\w+)\s+(?:service|app|application)/i],
      ['user_id', /user\s+(?:id\s+)?['"]?(\w+)['"]?/i],
      ['trace_id', /trace\s+(?:id\s+)?['"]?([\w-]+)['"]?/i],
      ['time', /(?:last|past|previous)\s+(\d+)\s+(second|minute|hour|day|week)s?/i],
      ['error_type', /(\w+Error|\w+Exception)/i],
    ]);
  }

  private detectIntent(query: string): QueryIntent {
    let maxScore = 0;
    let detectedIntent: QueryIntent = 'general_search';

    for (const [intent, patterns] of this.intentPatterns.entries()) {
      let score = 0;
      for (const pattern of patterns) {
        if (pattern.test(query)) {
          score++;
        }
      }

      if (score > maxScore) {
        maxScore = score;
        detectedIntent = intent;
      }
    }

    return detectedIntent;
  }

  private extractEntities(query: string): QueryEntity[] {
    const entities: QueryEntity[] = [];

    for (const [type, pattern] of this.entityPatterns.entries()) {
      const matches = query.matchAll(new RegExp(pattern, 'gi'));
      
      for (const match of matches) {
        const value = match[1] || match[0];
        entities.push({
          type,
          value: value.trim(),
          confidence: 0.8,
        });
      }
    }

    return entities;
  }

  private applyEntityToFilter(entity: QueryEntity, filters: SearchFilters): void {
    switch (entity.type) {
      case 'level':
        if (!filters.levels) filters.levels = [];
        filters.levels.push(entity.value.toLowerCase());
        break;
      
      case 'service':
        if (!filters.services) filters.services = [];
        filters.services.push(entity.value);
        break;
      
      case 'user_id':
        if (!filters.userIds) filters.userIds = [];
        filters.userIds.push(entity.value);
        break;
      
      case 'trace_id':
        if (!filters.traceIds) filters.traceIds = [];
        filters.traceIds.push(entity.value);
        break;
      
      case 'error_type':
        // Could be used for more specific filtering
        break;
    }
  }

  private extractAdvancedTimeRange(query: string): TimeRange | undefined {
    const lowerQuery = query.toLowerCase();

    // Relative time patterns
    const relativePatterns = [
      { pattern: /last\s+(\d+)\s+second/i, unit: 'seconds' as const },
      { pattern: /last\s+(\d+)\s+minute/i, unit: 'minutes' as const },
      { pattern: /last\s+(\d+)\s+hour/i, unit: 'hours' as const },
      { pattern: /last\s+(\d+)\s+day/i, unit: 'days' as const },
    ];

    for (const { pattern, unit } of relativePatterns) {
      const match = query.match(pattern);
      if (match) {
        const value = parseInt(match[1]);
        const multiplier = {
          seconds: 1000,
          minutes: 60 * 1000,
          hours: 60 * 60 * 1000,
          days: 24 * 60 * 60 * 1000,
        }[unit];

        return {
          start: new Date(Date.now() - value * multiplier),
          relative: { value, unit },
        };
      }
    }

    // Named time ranges
    if (lowerQuery.includes('today')) {
      const today = new Date();
      today.setHours(0, 0, 0, 0);
      return { start: today };
    }

    if (lowerQuery.includes('yesterday')) {
      const yesterday = new Date();
      yesterday.setDate(yesterday.getDate() - 1);
      yesterday.setHours(0, 0, 0, 0);
      const endOfYesterday = new Date(yesterday);
      endOfYesterday.setHours(23, 59, 59, 999);
      return { start: yesterday, end: endOfYesterday };
    }

    if (lowerQuery.includes('this week')) {
      const now = new Date();
      const startOfWeek = new Date(now);
      startOfWeek.setDate(now.getDate() - now.getDay());
      startOfWeek.setHours(0, 0, 0, 0);
      return { start: startOfWeek };
    }

    return undefined;
  }

  private calculateConfidence(
    intent: QueryIntent,
    entities: QueryEntity[],
    query: string
  ): number {
    let confidence = 0.5; // Base confidence

    // Boost confidence for specific intents
    if (intent !== 'general_search') {
      confidence += 0.2;
    }

    // Boost for number of entities found
    confidence += Math.min(entities.length * 0.1, 0.3);

    // Reduce confidence for very short or very long queries
    const wordCount = query.split(/\s+/).length;
    if (wordCount < 3 || wordCount > 20) {
      confidence -= 0.1;
    }

    return Math.max(0, Math.min(1, confidence));
  }

  private getOptionsForIntent(intent: QueryIntent): SearchOptions {
    const baseOptions: SearchOptions = {
      limit: 100,
      highlightMatches: true,
    };

    switch (intent) {
      case 'find_errors':
        return {
          ...baseOptions,
          includeContext: true,
          contextSize: 3,
          findSimilar: true,
        };

      case 'trace_request':
        return {
          ...baseOptions,
          includeContext: true,
          contextSize: 10,
          correlate: true,
          sortBy: 'timestamp',
          sortOrder: 'asc',
        };

      case 'find_user_activity':
        return {
          ...baseOptions,
          includeContext: true,
          sortBy: 'timestamp',
          sortOrder: 'asc',
          limit: 200,
        };

      case 'performance_analysis':
        return {
          ...baseOptions,
          includeContext: true,
          contextSize: 5,
          sortBy: 'timestamp',
        };

      case 'correlation':
        return {
          ...baseOptions,
          includeContext: true,
          contextSize: 5,
          correlate: true,
          findSimilar: true,
        };

      default:
        return baseOptions;
    }
  }

  private extractCleanQuery(query: string, entities: QueryEntity[]): string {
    let cleanQuery = query;

    // Remove entity text from query
    for (const entity of entities) {
      // Remove common patterns
      cleanQuery = cleanQuery.replace(
        new RegExp(`\\b${entity.value}\\b`, 'gi'),
        ''
      );
    }

    // Remove common filter words
    const filterWords = [
      'show', 'find', 'get', 'all', 'from', 'in', 'the',
      'for', 'with', 'last', 'past', 'today', 'yesterday',
      'service', 'user', 'trace', 'error', 'errors',
    ];

    for (const word of filterWords) {
      cleanQuery = cleanQuery.replace(
        new RegExp(`\\b${word}\\b`, 'gi'),
        ''
      );
    }

    // Clean up extra whitespace
    cleanQuery = cleanQuery.replace(/\s+/g, ' ').trim();

    return cleanQuery || query; // Fall back to original if nothing left
  }
}
