/**
 * Data Loss Prevention (DLP) Engine for Logixia
 * 
 * Scans log content for sensitive information, enforces security policies,
 * and quarantines suspicious log entries
 */

import { DLPConfig, DLPViolation, SecuritySeverity } from './security-manager';
import { PIIDetector, IPIIDetector, PIIMatch } from './pii-detector';
import { LogEntry } from '../types';

/**
 * DLP policy rule
 */
export interface DLPRule {
  id: string;
  name: string;
  description: string;
  pattern: RegExp | string;
  severity: SecuritySeverity;
  action: 'alert' | 'quarantine' | 'block' | 'redact';
  threshold?: number; // 0-1 value
}

/**
 * Quarantined log entry
 */
export interface QuarantinedEntry {
  id: string;
  timestamp: Date;
  entry: LogEntry;
  violations: DLPViolation[];
  status: 'pending' | 'approved' | 'rejected';
  reviewedBy?: string;
  reviewedAt?: Date;
  notes?: string;
}

/**
 * Interface for DLP engine
 */
export interface IDLPEngine {
  scanContent(content: string): Promise<DLPViolation[]>;
  scanLogEntry(entry: LogEntry): Promise<DLPViolation[]>;
  quarantineEntry(entry: LogEntry, violations: DLPViolation[]): Promise<string>;
  getQuarantinedEntry(id: string): Promise<QuarantinedEntry | null>;
  listQuarantinedEntries(status?: 'pending' | 'approved' | 'rejected'): Promise<QuarantinedEntry[]>;
  reviewQuarantinedEntry(id: string, action: 'approve' | 'reject', userId: string, notes?: string): Promise<void>;
  addRule(rule: DLPRule): void;
  removeRule(ruleId: string): boolean;
  isEnabled(): boolean;
}

/**
 * Default implementation of DLP engine
 */
export class DLPEngine implements IDLPEngine {
  private config: DLPConfig;
  private piiDetector?: IPIIDetector;
  private rules: DLPRule[] = [];
  private quarantinedEntries: Map<string, QuarantinedEntry> = new Map();

  constructor(config: DLPConfig, piiDetector?: IPIIDetector) {
    this.config = config || { enabled: false };
    this.piiDetector = piiDetector;
    
    // Initialize default rules
    if (this.config.enabled) {
      this.initializeDefaultRules();
    }
  }

  /**
   * Initialize default DLP rules
   */
  private initializeDefaultRules(): void {
    // API keys and tokens
    this.addRule({
      id: 'dlp-api-keys',
      name: 'API Key Detection',
      description: 'Detects API keys and access tokens in log content',
      pattern: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token)[:=\s]+[A-Za-z0-9_\-\.]{32,}\b/gi,
      severity: SecuritySeverity.HIGH,
      action: 'quarantine'
    });
    
    // Password detection
    this.addRule({
      id: 'dlp-passwords',
      name: 'Password Detection',
      description: 'Detects passwords in log content',
      pattern: /\b(?:password|passwd|pwd)[:=\s]+\S+\b/gi,
      severity: SecuritySeverity.HIGH,
      action: 'quarantine'
    });
    
    // Private keys
    this.addRule({
      id: 'dlp-private-keys',
      name: 'Private Key Detection',
      description: 'Detects private keys in log content',
      pattern: /-----BEGIN (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----[^-]*-----END (?:RSA|DSA|EC|OPENSSH) PRIVATE KEY-----/g,
      severity: SecuritySeverity.CRITICAL,
      action: 'quarantine'
    });
    
    // Database connection strings
    this.addRule({
      id: 'dlp-db-connection',
      name: 'Database Connection String',
      description: 'Detects database connection strings in log content',
      pattern: /\b(?:jdbc|mongodb|postgresql|mysql|redis):\/\/[^\s]+/gi,
      severity: SecuritySeverity.HIGH,
      action: 'alert'
    });
    
    // AWS access keys
    this.addRule({
      id: 'dlp-aws-keys',
      name: 'AWS Access Key',
      description: 'Detects AWS access keys in log content',
      pattern: /\b(?:AKIA|A3T|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}\b/g,
      severity: SecuritySeverity.CRITICAL,
      action: 'quarantine'
    });
    
    // Internal IP addresses
    this.addRule({
      id: 'dlp-internal-ip',
      name: 'Internal IP Address',
      description: 'Detects internal IP addresses in log content',
      pattern: /\b(?:10\.|172\.(?:1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)[0-9]{1,3}\.[0-9]{1,3}\b/g,
      severity: SecuritySeverity.MEDIUM,
      action: 'alert'
    });
  }

  /**
   * Check if DLP is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled === true;
  }

  /**
   * Add a DLP rule
   * @param rule Rule to add
   */
  addRule(rule: DLPRule): void {
    // Convert string patterns to RegExp if needed
    if (typeof rule.pattern === 'string') {
      rule.pattern = new RegExp(rule.pattern, 'g');
    }
    
    // Check if rule with this ID already exists
    const existingRuleIndex = this.rules.findIndex(r => r.id === rule.id);
    if (existingRuleIndex >= 0) {
      this.rules[existingRuleIndex] = rule;
    } else {
      this.rules.push(rule);
    }
  }

  /**
   * Remove a DLP rule
   * @param ruleId Rule ID to remove
   * @returns True if rule was removed, false if not found
   */
  removeRule(ruleId: string): boolean {
    const initialLength = this.rules.length;
    this.rules = this.rules.filter(rule => rule.id !== ruleId);
    return this.rules.length < initialLength;
  }

  /**
   * Scan content for DLP violations
   * @param content Content to scan
   * @returns Array of DLP violations
   */
  async scanContent(content: string): Promise<DLPViolation[]> {
    if (!this.isEnabled() || !content) {
      return [];
    }
    
    const violations: DLPViolation[] = [];
    
    // Apply DLP rules
    for (const rule of this.rules) {
      const pattern = rule.pattern as RegExp;
      let match;
      
      // Reset the regex to start from the beginning
      pattern.lastIndex = 0;
      
      // Find all matches
      while ((match = pattern.exec(content)) !== null) {
        violations.push({
          type: 'sensitive_content',
          description: `${rule.name}: ${rule.description}`,
          severity: rule.severity,
          content: match[0],
          timestamp: new Date(),
          metadata: {
            ruleId: rule.id,
            action: rule.action,
            matchIndex: match.index,
            matchLength: match[0].length
          }
        });
      }
    }
    
    // Use PII detector if available
    if (this.piiDetector?.isEnabled()) {
      try {
        const piiMatches = await this.piiDetector.detect(content);
        
        // Convert PII matches to DLP violations
        for (const match of piiMatches) {
          // Skip if confidence is below threshold
          if (match.confidence < (this.config.quarantineThreshold || 0.8)) {
            continue;
          }
          
          violations.push({
            type: 'sensitive_content',
            description: `PII detected: ${match.type}`,
            severity: SecuritySeverity.HIGH,
            content: match.value,
            timestamp: new Date(),
            metadata: {
              piiType: match.type,
              confidence: match.confidence,
              matchIndex: match.startIndex,
              matchLength: match.endIndex - match.startIndex,
              action: 'redact'
            }
          });
        }
      } catch (error) {
        console.error('Error detecting PII for DLP:', error);
      }
    }
    
    return violations;
  }

  /**
   * Scan a log entry for DLP violations
   * @param entry Log entry to scan
   * @returns Array of DLP violations
   */
  async scanLogEntry(entry: LogEntry): Promise<DLPViolation[]> {
    if (!this.isEnabled()) {
      return [];
    }
    
    const violations: DLPViolation[] = [];
    
    // Scan message
    if (entry.message) {
      const messageViolations = await this.scanContent(entry.message);
      for (const violation of messageViolations) {
        violation.logEntryId = entry.auditId || 'unknown';
        violations.push(violation);
      }
    }
    
    // Scan payload fields
    if (entry.payload) {
      // Convert payload to string for scanning
      const payloadStr = JSON.stringify(entry.payload);
      const payloadViolations = await this.scanContent(payloadStr);
      
      for (const violation of payloadViolations) {
        violation.logEntryId = entry.auditId || 'unknown';
        violations.push(violation);
      }
    }
    
    return violations;
  }

  /**
   * Quarantine a log entry
   * @param entry Log entry to quarantine
   * @param violations DLP violations
   * @returns Quarantine ID
   */
  async quarantineEntry(entry: LogEntry, violations: DLPViolation[]): Promise<string> {
    const id = crypto.randomUUID();
    
    const quarantinedEntry: QuarantinedEntry = {
      id,
      timestamp: new Date(),
      entry,
      violations,
      status: 'pending'
    };
    
    this.quarantinedEntries.set(id, quarantinedEntry);
    return id;
  }

  /**
   * Get a quarantined entry by ID
   * @param id Quarantine ID
   * @returns Quarantined entry or null if not found
   */
  async getQuarantinedEntry(id: string): Promise<QuarantinedEntry | null> {
    return this.quarantinedEntries.get(id) || null;
  }

  /**
   * List quarantined entries
   * @param status Optional status filter
   * @returns Array of quarantined entries
   */
  async listQuarantinedEntries(status?: 'pending' | 'approved' | 'rejected'): Promise<QuarantinedEntry[]> {
    const entries = Array.from(this.quarantinedEntries.values());
    
    if (status) {
      return entries.filter(entry => entry.status === status);
    }
    
    return entries;
  }

  /**
   * Review a quarantined entry
   * @param id Quarantine ID
   * @param action Action to take (approve or reject)
   * @param userId User ID performing the review
   * @param notes Optional notes
   */
  async reviewQuarantinedEntry(id: string, action: 'approve' | 'reject', userId: string, notes?: string): Promise<void> {
    const entry = this.quarantinedEntries.get(id);
    if (!entry) {
      throw new Error(`Quarantined entry not found: ${id}`);
    }
    
    entry.status = action === 'approve' ? 'approved' : 'rejected';
    entry.reviewedBy = userId;
    entry.reviewedAt = new Date();
    
    if (notes) {
      entry.notes = notes;
    }
    
    this.quarantinedEntries.set(id, entry);
  }
}