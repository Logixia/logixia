/**
 * Pattern recognition engine for detecting and analyzing log patterns
 */

import { LogEntry } from '../../types';
import { LogPattern, AnomalyDetection } from '../types';

/**
 * Pattern recognition engine for log analysis
 */
export class PatternRecognitionEngine {
  private patterns: Map<string, LogPattern> = new Map();
  private patternFrequencies: Map<string, number> = new Map();

  constructor(private options?: {
    minFrequency?: number;
    maxPatterns?: number;
    anomalyThreshold?: number;
  }) {
    this.options = {
      minFrequency: 3,
      maxPatterns: 1000,
      anomalyThreshold: 0.3,
      ...options,
    };
  }

  /**
   * Analyze logs and detect patterns
   */
  async analyzePatterns(logs: LogEntry[]): Promise<LogPattern[]> {
    // Extract patterns from log messages
    const messagePatterns = this.extractMessagePatterns(logs);

    // Extract error patterns
    const errorPatterns = this.extractErrorPatterns(logs);

    // Extract timing patterns
    const timingPatterns = this.extractTimingPatterns(logs);

    // Combine all patterns
    const allPatterns = [
      ...messagePatterns,
      ...errorPatterns,
      ...timingPatterns,
    ];

    // Filter by frequency
    const frequentPatterns = allPatterns.filter(
      (p) => p.frequency >= (this.options?.minFrequency || 3)
    );

    // Sort by frequency
    frequentPatterns.sort((a, b) => b.frequency - a.frequency);

    // Limit number of patterns
    const limitedPatterns = frequentPatterns.slice(
      0,
      this.options?.maxPatterns || 1000
    );

    // Store patterns
    for (const pattern of limitedPatterns) {
      this.patterns.set(pattern.id, pattern);
    }

    return limitedPatterns;
  }

  /**
   * Detect anomalies in logs
   */
  async detectAnomalies(logs: LogEntry[]): Promise<AnomalyDetection[]> {
    const anomalies: AnomalyDetection[] = [];

    for (const log of logs) {
      const anomalyScore = await this.calculateAnomalyScore(log);
      
      if (anomalyScore > (this.options?.anomalyThreshold || 0.3)) {
        anomalies.push({
          log,
          anomalyScore,
          reason: this.generateAnomalyReason(log, anomalyScore),
          deviations: this.findDeviations(log),
        });
      }
    }

    return anomalies.sort((a, b) => b.anomalyScore - a.anomalyScore);
  }

  /**
   * Find patterns matching a log entry
   */
  findMatchingPatterns(log: LogEntry): LogPattern[] {
    const matching: LogPattern[] = [];

    for (const pattern of this.patterns.values()) {
      if (this.doesLogMatchPattern(log, pattern)) {
        matching.push(pattern);
      }
    }

    return matching;
  }

  /**
   * Get all detected patterns
   */
  getPatterns(): LogPattern[] {
    return Array.from(this.patterns.values());
  }

  /**
   * Get pattern by ID
   */
  getPattern(patternId: string): LogPattern | undefined {
    return this.patterns.get(patternId);
  }

  // Private methods

  private extractMessagePatterns(logs: LogEntry[]): LogPattern[] {
    const patternMap = new Map<string, { examples: LogEntry[]; count: number }>();

    for (const log of logs) {
      // Normalize message by replacing numbers and IDs
      const normalizedMessage = this.normalizeMessage(log.message);
      
      if (!patternMap.has(normalizedMessage)) {
        patternMap.set(normalizedMessage, { examples: [], count: 0 });
      }
      
      const pattern = patternMap.get(normalizedMessage)!;
      if (pattern.examples.length < 3) {
        pattern.examples.push(log);
      }
      pattern.count++;
    }

    // Convert to LogPattern array
    return Array.from(patternMap.entries()).map(([pattern, data], index) => ({
      id: `msg_pattern_${index}`,
      pattern,
      examples: data.examples,
      frequency: data.count,
      lastSeen: data.examples[data.examples.length - 1]?.timestamp 
        ? new Date(data.examples[data.examples.length - 1].timestamp)
        : new Date(),
      category: 'message',
    }));
  }

  private extractErrorPatterns(logs: LogEntry[]): LogPattern[] {
    const errorLogs = logs.filter((log) => log.level === 'error' || log.error);
    const patternMap = new Map<string, { examples: LogEntry[]; count: number }>();

    for (const log of errorLogs) {
      const errorPattern = this.extractErrorPattern(log);
      
      if (!patternMap.has(errorPattern)) {
        patternMap.set(errorPattern, { examples: [], count: 0 });
      }
      
      const pattern = patternMap.get(errorPattern)!;
      if (pattern.examples.length < 3) {
        pattern.examples.push(log);
      }
      pattern.count++;
    }

    return Array.from(patternMap.entries()).map(([pattern, data], index) => ({
      id: `error_pattern_${index}`,
      pattern,
      examples: data.examples,
      frequency: data.count,
      lastSeen: data.examples[data.examples.length - 1]?.timestamp
        ? new Date(data.examples[data.examples.length - 1].timestamp)
        : new Date(),
      category: 'error',
      severity: 'high',
    }));
  }

  private extractTimingPatterns(logs: LogEntry[]): LogPattern[] {
    const patterns: LogPattern[] = [];
    const hourCounts = new Map<number, number>();

    // Analyze temporal patterns
    for (const log of logs) {
      const hour = new Date(log.timestamp).getHours();
      hourCounts.set(hour, (hourCounts.get(hour) || 0) + 1);
    }

    // Find peak hours
    const peakHour = Array.from(hourCounts.entries())
      .sort((a, b) => b[1] - a[1])[0];

    if (peakHour) {
      patterns.push({
        id: 'timing_peak',
        pattern: `Peak activity at hour ${peakHour[0]}`,
        examples: logs.slice(0, 3),
        frequency: peakHour[1],
        lastSeen: new Date(),
        category: 'timing',
      });
    }

    return patterns;
  }

  private normalizeMessage(message: string): string {
    return message
      .replace(/\d+/g, '<NUM>') // Replace numbers
      .replace(/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}/gi, '<UUID>') // Replace UUIDs
      .replace(/[a-f0-9]{32}/gi, '<HASH>') // Replace hashes
      .replace(/"[^"]*"/g, '<STRING>') // Replace quoted strings
      .replace(/\b\w+@\w+\.\w+\b/g, '<EMAIL>') // Replace emails
      .trim();
  }

  private extractErrorPattern(log: LogEntry): string {
    if (log.error) {
      return `${log.error.name}: ${this.normalizeMessage(log.error.message || '')}`;
    }
    return this.normalizeMessage(log.message);
  }

  private async calculateAnomalyScore(log: LogEntry): Promise<number> {
    let score = 0;

    // Check if log matches known patterns
    const matchingPatterns = this.findMatchingPatterns(log);
    if (matchingPatterns.length === 0) {
      score += 0.3; // Unknown pattern
    }

    // Check error frequency
    if (log.level === 'error') {
      const errorPattern = this.extractErrorPattern(log);
      const frequency = this.patternFrequencies.get(errorPattern) || 0;
      if (frequency < 2) {
        score += 0.3; // Rare error
      }
    }

    // Check time of day
    const hour = new Date(log.timestamp).getHours();
    if (hour < 6 || hour > 22) {
      score += 0.2; // Off-hours activity
    }

    return Math.min(score, 1.0);
  }

  private generateAnomalyReason(log: LogEntry, score: number): string {
    const reasons: string[] = [];

    if (score > 0.7) {
      reasons.push('Highly unusual log entry');
    } else if (score > 0.5) {
      reasons.push('Moderately unusual log entry');
    } else {
      reasons.push('Slightly unusual log entry');
    }

    const matchingPatterns = this.findMatchingPatterns(log);
    if (matchingPatterns.length === 0) {
      reasons.push('does not match any known patterns');
    }

    if (log.level === 'error') {
      reasons.push('rare error type');
    }

    const hour = new Date(log.timestamp).getHours();
    if (hour < 6 || hour > 22) {
      reasons.push('occurred during off-hours');
    }

    return reasons.join(', ');
  }

  private findDeviations(log: LogEntry): string[] {
    const deviations: string[] = [];

    // Check for missing standard fields
    if (!log.traceId) deviations.push('Missing trace ID');
    if (!log.context) deviations.push('Missing context');

    // Check for unusual payload
    if (log.payload && Object.keys(log.payload).length > 20) {
      deviations.push('Unusually large payload');
    }

    // Check for stack trace in non-error logs
    if (log.level !== 'error' && log.message.includes('at ')) {
      deviations.push('Stack trace in non-error log');
    }

    return deviations;
  }

  private doesLogMatchPattern(log: LogEntry, pattern: LogPattern): boolean {
    const normalizedMessage = this.normalizeMessage(log.message);
    
    if (pattern.regex) {
      return pattern.regex.test(log.message);
    }
    
    return normalizedMessage === pattern.pattern;
  }
}
