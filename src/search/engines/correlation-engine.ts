/**
 * Correlation engine for finding relationships between log entries
 */

import { LogEntry } from '../../types';
import {
  CorrelatedLogs,
  RelatedLog,
  RelationshipType,
  TimelineEvent,
  LogCorrelationSummary,
} from '../types';

/**
 * Correlation engine for log analysis
 */
export class CorrelationEngine {
  constructor(
    private options?: {
      maxCorrelationDistance?: number;
      temporalWindowMs?: number;
      minSimilarityScore?: number;
    }
  ) {
    this.options = {
      maxCorrelationDistance: 100,
      temporalWindowMs: 5 * 60 * 1000, // 5 minutes
      minSimilarityScore: 0.3,
      ...options,
    };
  }

  /**
   * Find logs related to a given log entry
   */
  async findRelatedLogs(
    log: LogEntry,
    allLogs: LogEntry[],
    limit: number = 50
  ): Promise<RelatedLog[]> {
    const related: RelatedLog[] = [];

    for (const otherLog of allLogs) {
      if (otherLog === log) continue;

      const relationships = this.findRelationships(log, otherLog);
      
      for (const relationship of relationships) {
        const score = this.calculateRelationshipScore(relationship, log, otherLog);
        
        if (score > (this.options?.minSimilarityScore || 0.3)) {
          related.push({
            log: otherLog,
            relationship,
            score,
          });
        }
      }
    }

    // Deduplicate and sort by score
    const uniqueRelated = this.deduplicateRelatedLogs(related);
    return uniqueRelated
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);
  }

  /**
   * Correlate logs by multiple criteria
   */
  async correlateByMultipleCriteria(
    logs: LogEntry[],
    criteria: {
      traceId?: boolean;
      userId?: boolean;
      sessionId?: boolean;
      temporal?: boolean;
      errorCascade?: boolean;
    }
  ): Promise<Map<string, CorrelatedLogs>> {
    const correlations = new Map<string, CorrelatedLogs>();

    // Correlate by trace ID
    if (criteria.traceId) {
      const traceCorrelations = this.correlateByTraceId(logs);
      for (const [key, value] of traceCorrelations) {
        correlations.set(`trace_${key}`, value);
      }
    }

    // Correlate by user ID
    if (criteria.userId) {
      const userCorrelations = this.correlateByUserId(logs);
      for (const [key, value] of userCorrelations) {
        correlations.set(`user_${key}`, value);
      }
    }

    // Correlate by session ID
    if (criteria.sessionId) {
      const sessionCorrelations = this.correlateBySessionId(logs);
      for (const [key, value] of sessionCorrelations) {
        correlations.set(`session_${key}`, value);
      }
    }

    // Correlate by temporal proximity
    if (criteria.temporal) {
      const temporalCorrelations = this.correlateByTemporalProximity(logs);
      for (const [key, value] of temporalCorrelations) {
        correlations.set(`temporal_${key}`, value);
      }
    }

    // Correlate error cascades
    if (criteria.errorCascade) {
      const errorCorrelations = this.correlateErrorCascades(logs);
      for (const [key, value] of errorCorrelations) {
        correlations.set(`error_${key}`, value);
      }
    }

    return correlations;
  }

  /**
   * Build a timeline from correlated logs
   */
  buildTimeline(logs: LogEntry[]): TimelineEvent[] {
    const timeline: TimelineEvent[] = [];

    // Sort logs by timestamp
    const sortedLogs = [...logs].sort((a, b) =>
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    for (let i = 0; i < sortedLogs.length; i++) {
      const log = sortedLogs[i];
      const eventType = this.determineEventType(log, sortedLogs, i);
      
      const event: TimelineEvent = {
        timestamp: new Date(log.timestamp),
        log,
        eventType,
      };

      // Calculate duration for start/end events
      if (eventType === 'start' && i < sortedLogs.length - 1) {
        const endEvent = sortedLogs
          .slice(i + 1)
          .find((l) => this.determineEventType(l, sortedLogs, sortedLogs.indexOf(l)) === 'end');
        
        if (endEvent) {
          event.duration = new Date(endEvent.timestamp).getTime() - new Date(log.timestamp).getTime();
        }
      }

      timeline.push(event);
    }

    return timeline;
  }

  /**
   * Analyze error cascades
   */
  async analyzeErrorCascade(
    logs: LogEntry[]
  ): Promise<{ rootCause?: LogEntry; cascade: LogEntry[]; impactedServices: string[] }> {
    const errors = logs.filter((log) => log.level === 'error');
    
    if (errors.length === 0) {
      return { cascade: [], impactedServices: [] };
    }

    // Find root cause (earliest error)
    const rootCause = errors.reduce((earliest, current) =>
      new Date(current.timestamp) < new Date(earliest.timestamp) ? current : earliest
    );

    // Build cascade
    const cascade = this.buildErrorCascade(rootCause, errors);

    // Get impacted services
    const impactedServices = [...new Set(cascade.map((log) => log.appName))];

    return {
      rootCause,
      cascade,
      impactedServices,
    };
  }

  // Private methods

  private correlateByTraceId(logs: LogEntry[]): Map<string, CorrelatedLogs> {
    const correlations = new Map<string, LogEntry[]>();

    for (const log of logs) {
      if (!log.traceId) continue;

      if (!correlations.has(log.traceId)) {
        correlations.set(log.traceId, []);
      }
      correlations.get(log.traceId)!.push(log);
    }

    return this.convertToCorrelatedLogs(correlations, 'trace');
  }

  private correlateByUserId(logs: LogEntry[]): Map<string, CorrelatedLogs> {
    const correlations = new Map<string, LogEntry[]>();

    for (const log of logs) {
      const userId = log.payload?.userId as string | undefined;
      if (!userId) continue;

      if (!correlations.has(userId)) {
        correlations.set(userId, []);
      }
      correlations.get(userId)!.push(log);
    }

    return this.convertToCorrelatedLogs(correlations, 'user');
  }

  private correlateBySessionId(logs: LogEntry[]): Map<string, CorrelatedLogs> {
    const correlations = new Map<string, LogEntry[]>();

    for (const log of logs) {
      const sessionId = log.payload?.sessionId as string | undefined;
      if (!sessionId) continue;

      if (!correlations.has(sessionId)) {
        correlations.set(sessionId, []);
      }
      correlations.get(sessionId)!.push(log);
    }

    return this.convertToCorrelatedLogs(correlations, 'session');
  }

  private correlateByTemporalProximity(logs: LogEntry[]): Map<string, CorrelatedLogs> {
    const correlations = new Map<string, LogEntry[]>();
    const sortedLogs = [...logs].sort((a, b) =>
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );

    let currentGroup: LogEntry[] = [];
    let groupStartTime: number | null = null;

    for (const log of sortedLogs) {
      const logTime = new Date(log.timestamp).getTime();

      if (groupStartTime === null) {
        groupStartTime = logTime;
        currentGroup = [log];
      } else if (logTime - groupStartTime <= (this.options?.temporalWindowMs || 300000)) {
        currentGroup.push(log);
      } else {
        // Save current group
        if (currentGroup.length > 1) {
          const groupKey = `${groupStartTime}`;
          correlations.set(groupKey, currentGroup);
        }
        
        // Start new group
        groupStartTime = logTime;
        currentGroup = [log];
      }
    }

    // Save last group
    if (currentGroup.length > 1 && groupStartTime !== null) {
      correlations.set(`${groupStartTime}`, currentGroup);
    }

    return this.convertToCorrelatedLogs(correlations, 'temporal');
  }

  private correlateErrorCascades(logs: LogEntry[]): Map<string, CorrelatedLogs> {
    const correlations = new Map<string, LogEntry[]>();
    const errors = logs.filter((log) => log.level === 'error');

    for (const error of errors) {
      const cascade = this.buildErrorCascade(error, logs);
      
      if (cascade.length > 1) {
        const key = `${error.timestamp}_${error.message.substring(0, 20)}`;
        correlations.set(key, cascade);
      }
    }

    return this.convertToCorrelatedLogs(correlations, 'error_cascade');
  }

  private buildErrorCascade(rootError: LogEntry, allLogs: LogEntry[]): LogEntry[] {
    const cascade: LogEntry[] = [rootError];
    const rootTime = new Date(rootError.timestamp).getTime();
    const windowMs = this.options?.temporalWindowMs || 300000;

    // Find related errors within time window
    for (const log of allLogs) {
      if (log === rootError) continue;

      const logTime = new Date(log.timestamp).getTime();
      const timeDiff = logTime - rootTime;

      if (
        timeDiff > 0 &&
        timeDiff <= windowMs &&
        (log.level === 'error' || log.level === 'warn') &&
        (log.traceId === rootError.traceId || log.appName === rootError.appName)
      ) {
        cascade.push(log);
      }
    }

    return cascade.sort((a, b) =>
      new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
    );
  }

  private findRelationships(log1: LogEntry, log2: LogEntry): RelationshipType[] {
    const relationships: RelationshipType[] = [];

    // Same trace
    if (log1.traceId && log1.traceId === log2.traceId) {
      relationships.push('same_trace');
    }

    // Same user
    const user1 = log1.payload?.userId;
    const user2 = log2.payload?.userId;
    if (user1 && user1 === user2) {
      relationships.push('same_user');
    }

    // Same session
    const session1 = log1.payload?.sessionId;
    const session2 = log2.payload?.sessionId;
    if (session1 && session1 === session2) {
      relationships.push('same_session');
    }

    // Temporal proximity
    const time1 = new Date(log1.timestamp).getTime();
    const time2 = new Date(log2.timestamp).getTime();
    if (Math.abs(time1 - time2) <= (this.options?.temporalWindowMs || 300000)) {
      relationships.push('temporal_proximity');
    }

    // Error cascade
    if (
      (log1.level === 'error' || log2.level === 'error') &&
      time2 > time1 &&
      time2 - time1 <= (this.options?.temporalWindowMs || 300000)
    ) {
      relationships.push('error_cascade');
    }

    // Similar pattern
    if (this.haveSimilarPattern(log1, log2)) {
      relationships.push('similar_pattern');
    }

    return relationships;
  }

  private calculateRelationshipScore(
    relationship: RelationshipType,
    log1: LogEntry,
    log2: LogEntry
  ): number {
    const weights: Record<RelationshipType, number> = {
      same_trace: 0.9,
      same_user: 0.7,
      same_session: 0.8,
      temporal_proximity: 0.4,
      error_cascade: 0.8,
      similar_pattern: 0.5,
    };

    let score = weights[relationship] || 0.3;

    // Boost score for same service
    if (log1.appName === log2.appName) {
      score += 0.1;
    }

    return Math.min(score, 1.0);
  }

  private haveSimilarPattern(log1: LogEntry, log2: LogEntry): boolean {
    const normalized1 = this.normalizeMessage(log1.message);
    const normalized2 = this.normalizeMessage(log2.message);
    
    return normalized1 === normalized2;
  }

  private normalizeMessage(message: string): string {
    return message
      .replace(/\d+/g, '<NUM>')
      .replace(/[a-f0-9-]{36}/gi, '<UUID>')
      .toLowerCase()
      .trim();
  }

  private determineEventType(
    log: LogEntry,
    allLogs: LogEntry[],
    index: number
  ): TimelineEvent['eventType'] {
    const message = log.message.toLowerCase();

    if (message.includes('start') || message.includes('begin') || message.includes('initiated')) {
      return 'start';
    }

    if (message.includes('end') || message.includes('complete') || message.includes('finished')) {
      return 'end';
    }

    if (log.level === 'error') {
      return 'error';
    }

    if (message.includes('milestone') || message.includes('checkpoint')) {
      return 'milestone';
    }

    return 'info';
  }

  private deduplicateRelatedLogs(related: RelatedLog[]): RelatedLog[] {
    const seen = new Set<LogEntry>();
    const unique: RelatedLog[] = [];

    for (const item of related) {
      if (!seen.has(item.log)) {
        seen.add(item.log);
        unique.push(item);
      }
    }

    return unique;
  }

  private convertToCorrelatedLogs(
    correlations: Map<string, LogEntry[]>,
    type: string
  ): Map<string, CorrelatedLogs> {
    const result = new Map<string, CorrelatedLogs>();

    for (const [key, logs] of correlations.entries()) {
      if (logs.length < 2) continue; // Skip single log entries

      const timeline = this.buildTimeline(logs);
      const summary = this.generateSummary(logs);

      result.set(key, {
        correlationKey: key,
        traceId: type === 'trace' ? key : undefined,
        logs,
        timeline,
        summary,
      });
    }

    return result;
  }

  private generateSummary(logs: LogEntry[]): LogCorrelationSummary {
    const errorCount = logs.filter((l) => l.level === 'error').length;
    const warningCount = logs.filter((l) => l.level === 'warn').length;
    const services = [...new Set(logs.map((l) => l.appName))];

    // Calculate duration
    let duration: number | undefined;
    if (logs.length > 1) {
      const sorted = [...logs].sort((a, b) =>
        new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
      );
      const start = new Date(sorted[0].timestamp).getTime();
      const end = new Date(sorted[sorted.length - 1].timestamp).getTime();
      duration = end - start;
    }

    return {
      totalLogs: logs.length,
      errorCount,
      warningCount,
      services,
      duration,
    };
  }
}
