/**
 * Security Monitoring Engine for Logixia
 * 
 * Detects security threats, anomalies, and policy violations
 * Provides real-time alerts and automated incident response
 */

import { SecurityMonitoringConfig, SecurityAlert, SecuritySeverity, SecurityEventType } from './security-manager';
import { AuditTrail, IAuditTrail, AuditAnomaly } from './audit-trail';
import { LogEntry } from '../types';

/**
 * Security incident
 */
export interface SecurityIncident {
  id: string;
  type: 'threat' | 'anomaly' | 'policy_violation' | 'tamper';
  description: string;
  severity: SecuritySeverity;
  timestamp: Date;
  status: 'open' | 'investigating' | 'resolved' | 'false_positive';
  alerts: SecurityAlert[];
  assignedTo?: string;
  resolution?: string;
  metadata?: Record<string, any>;
}

/**
 * Security rule
 */
export interface SecurityRule {
  id: string;
  name: string;
  description: string;
  condition: (entry: LogEntry) => boolean;
  severity: SecuritySeverity;
  enabled: boolean;
}

/**
 * Interface for security monitoring engine
 */
export interface ISecurityMonitoring {
  monitorLogEntry(entry: LogEntry): Promise<SecurityAlert[]>;
  detectAnomalies(timeframe?: number): Promise<AuditAnomaly[]>;
  createAlert(alert: SecurityAlert): Promise<void>;
  createIncident(alerts: SecurityAlert[]): Promise<string>;
  getIncident(id: string): Promise<SecurityIncident | null>;
  updateIncidentStatus(id: string, status: 'open' | 'investigating' | 'resolved' | 'false_positive', userId?: string, notes?: string): Promise<void>;
  addRule(rule: SecurityRule): void;
  removeRule(ruleId: string): boolean;
  isEnabled(): boolean;
}

/**
 * Default implementation of security monitoring engine
 */
export class SecurityMonitoring implements ISecurityMonitoring {
  private config: SecurityMonitoringConfig;
  private auditTrail?: IAuditTrail;
  private rules: SecurityRule[] = [];
  private alerts: SecurityAlert[] = [];
  private incidents: Map<string, SecurityIncident> = new Map();
  private alertHandlers: ((alert: SecurityAlert) => Promise<void>)[] = [];

  constructor(config: SecurityMonitoringConfig, auditTrail?: IAuditTrail) {
    this.config = config || { enabled: false };
    this.auditTrail = auditTrail;
    
    // Add default alert handler if provided
    if (this.config.alertHandler) {
      this.alertHandlers.push(this.config.alertHandler);
    }
    
    // Initialize default rules
    if (this.config.enabled) {
      this.initializeDefaultRules();
    }
  }

  /**
   * Initialize default security rules
   */
  private initializeDefaultRules(): void {
    // Failed authentication attempts
    this.addRule({
      id: 'sec-failed-auth',
      name: 'Failed Authentication',
      description: 'Detects failed authentication attempts',
      condition: (entry: LogEntry) => {
        const message = entry.message?.toLowerCase() || '';
        const payload = entry.payload || {};
        
        return (
          (message.includes('failed') && message.includes('authentication')) ||
          (message.includes('failed') && message.includes('login')) ||
          (payload.success === false && payload.event === 'authentication')
        );
      },
      severity: SecuritySeverity.MEDIUM,
      enabled: true
    });
    
    // Unauthorized access attempts
    this.addRule({
      id: 'sec-unauthorized',
      name: 'Unauthorized Access',
      description: 'Detects unauthorized access attempts',
      condition: (entry: LogEntry) => {
        const message = entry.message?.toLowerCase() || '';
        const payload = entry.payload || {};
        
        return (
          message.includes('unauthorized') ||
          message.includes('forbidden') ||
          message.includes('access denied') ||
          (payload.status === 401 || payload.status === 403)
        );
      },
      severity: SecuritySeverity.HIGH,
      enabled: true
    });
    
    // Suspicious activity
    this.addRule({
      id: 'sec-suspicious',
      name: 'Suspicious Activity',
      description: 'Detects suspicious activity patterns',
      condition: (entry: LogEntry) => {
        const message = entry.message?.toLowerCase() || '';
        const payload = entry.payload || {};
        
        return (
          message.includes('suspicious') ||
          message.includes('unusual') ||
          message.includes('unexpected') ||
          payload.suspicious === true
        );
      },
      severity: SecuritySeverity.MEDIUM,
      enabled: true
    });
    
    // Error spikes
    this.addRule({
      id: 'sec-error-spike',
      name: 'Error Spike',
      description: 'Detects unusual spikes in error rates',
      condition: (entry: LogEntry) => {
        return entry.level === 'error' && entry.payload?.errorCount > 10;
      },
      severity: SecuritySeverity.MEDIUM,
      enabled: true
    });
    
    // Configuration changes
    this.addRule({
      id: 'sec-config-change',
      name: 'Configuration Change',
      description: 'Detects sensitive configuration changes',
      condition: (entry: LogEntry) => {
        const message = entry.message?.toLowerCase() || '';
        const payload = entry.payload || {};
        
        return (
          message.includes('config') && (message.includes('change') || message.includes('update')) ||
          payload.event === 'configuration_change'
        );
      },
      severity: SecuritySeverity.LOW,
      enabled: true
    });
  }

  /**
   * Check if security monitoring is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled === true;
  }

  /**
   * Add a security rule
   * @param rule Rule to add
   */
  addRule(rule: SecurityRule): void {
    // Check if rule with this ID already exists
    const existingRuleIndex = this.rules.findIndex(r => r.id === rule.id);
    if (existingRuleIndex >= 0) {
      this.rules[existingRuleIndex] = rule;
    } else {
      this.rules.push(rule);
    }
  }

  /**
   * Remove a security rule
   * @param ruleId Rule ID to remove
   * @returns True if rule was removed, false if not found
   */
  removeRule(ruleId: string): boolean {
    const initialLength = this.rules.length;
    this.rules = this.rules.filter(rule => rule.id !== ruleId);
    return this.rules.length < initialLength;
  }

  /**
   * Monitor a log entry for security issues
   * @param entry Log entry to monitor
   * @returns Array of security alerts
   */
  async monitorLogEntry(entry: LogEntry): Promise<SecurityAlert[]> {
    if (!this.isEnabled()) {
      return [];
    }
    
    const alerts: SecurityAlert[] = [];
    
    // Apply security rules
    for (const rule of this.rules) {
      if (!rule.enabled) {
        continue;
      }
      
      try {
        if (rule.condition(entry)) {
          const alert: SecurityAlert = {
            type: 'policy_violation',
            description: `${rule.name}: ${rule.description}`,
            severity: rule.severity,
            timestamp: new Date(),
            source: 'security_rule',
            metadata: {
              ruleId: rule.id,
              logEntryId: entry.auditId || 'unknown',
              level: entry.level,
              message: entry.message
            }
          };
          
          alerts.push(alert);
          await this.createAlert(alert);
        }
      } catch (error) {
        console.error(`Error applying security rule ${rule.id}:`, error);
      }
    }
    
    return alerts;
  }

  /**
   * Detect anomalies in audit trail
   * @param timeframe Timeframe in hours (default: 24)
   * @returns Array of audit anomalies
   */
  async detectAnomalies(timeframe: number = 24): Promise<AuditAnomaly[]> {
    if (!this.isEnabled() || !this.auditTrail) {
      return [];
    }
    
    // Use audit trail's anomaly detection
    const anomalies = await this.auditTrail.detectAnomalies(timeframe);
    
    // Create alerts for anomalies
    for (const anomaly of anomalies) {
      const alert: SecurityAlert = {
        type: 'anomaly',
        description: anomaly.description,
        severity: anomaly.severity,
        timestamp: anomaly.timestamp,
        source: 'audit_anomaly',
        metadata: {
          anomalyType: anomaly.type,
          score: anomaly.score,
          relatedEntries: anomaly.relatedEntries
        }
      };
      
      await this.createAlert(alert);
    }
    
    return anomalies;
  }

  /**
   * Create a security alert
   * @param alert Security alert
   */
  async createAlert(alert: SecurityAlert): Promise<void> {
    if (!this.isEnabled()) {
      return;
    }
    
    // Store the alert
    this.alerts.push(alert);
    
    // Log to audit trail if available
    if (this.auditTrail) {
      await this.auditTrail.logSecurityEvent({
        type: SecurityEventType.SECURITY_VIOLATION,
        severity: alert.severity,
        description: alert.description,
        metadata: alert.metadata || {},
        timestamp: alert.timestamp
      });
    }
    
    // Notify alert handlers
    if (this.config.realTimeAlerts && this.alertHandlers.length > 0) {
      for (const handler of this.alertHandlers) {
        try {
          await handler(alert);
        } catch (error) {
          console.error('Error in alert handler:', error);
        }
      }
    }
    
    // Create incident for high severity alerts
    if (alert.severity === SecuritySeverity.HIGH || alert.severity === SecuritySeverity.CRITICAL) {
      await this.createIncident([alert]);
    }
  }

  /**
   * Create a security incident from alerts
   * @param alerts Alerts to include in the incident
   * @returns Incident ID
   */
  async createIncident(alerts: SecurityAlert[]): Promise<string> {
    if (!this.isEnabled() || alerts.length === 0) {
      return '';
    }
    
    // Determine highest severity
    let highestSeverity = SecuritySeverity.LOW;
    for (const alert of alerts) {
      if (this.getSeverityLevel(alert.severity) > this.getSeverityLevel(highestSeverity)) {
        highestSeverity = alert.severity;
      }
    }
    
    const id = crypto.randomUUID();
    const incident: SecurityIncident = {
      id,
      type: alerts[0].type,
      description: alerts.length === 1 
        ? alerts[0].description 
        : `Security incident with ${alerts.length} alerts`,
      severity: highestSeverity,
      timestamp: new Date(),
      status: 'open',
      alerts
    };
    
    this.incidents.set(id, incident);
    
    // Log to audit trail if available
    if (this.auditTrail) {
      await this.auditTrail.logSecurityEvent({
        type: SecurityEventType.SECURITY_VIOLATION,
        severity: incident.severity,
        description: `Security incident created: ${incident.description}`,
        metadata: {
          incidentId: id,
          alertCount: alerts.length
        },
        timestamp: incident.timestamp
      });
    }
    
    return id;
  }

  /**
   * Get a security incident by ID
   * @param id Incident ID
   * @returns Security incident or null if not found
   */
  async getIncident(id: string): Promise<SecurityIncident | null> {
    return this.incidents.get(id) || null;
  }

  /**
   * Update a security incident's status
   * @param id Incident ID
   * @param status New status
   * @param userId User ID making the change
   * @param notes Optional notes
   */
  async updateIncidentStatus(id: string, status: 'open' | 'investigating' | 'resolved' | 'false_positive', userId?: string, notes?: string): Promise<void> {
    const incident = this.incidents.get(id);
    if (!incident) {
      throw new Error(`Incident not found: ${id}`);
    }
    
    const oldStatus = incident.status;
    incident.status = status;
    
    if (status === 'resolved' || status === 'false_positive') {
      incident.resolution = notes || `Marked as ${status}`;
    }
    
    if (userId) {
      incident.assignedTo = userId;
    }
    
    this.incidents.set(id, incident);
    
    // Log to audit trail if available
    if (this.auditTrail) {
      await this.auditTrail.logSecurityEvent({
        type: SecurityEventType.SECURITY_VIOLATION,
        severity: SecuritySeverity.LOW,
        description: `Security incident status updated: ${oldStatus} -> ${status}`,
        metadata: {
          incidentId: id,
          oldStatus,
          newStatus: status,
          userId,
          notes
        },
        timestamp: new Date()
      });
    }
  }

  /**
   * Get numeric severity level for comparison
   * @param severity Security severity
   * @returns Numeric level
   */
  private getSeverityLevel(severity: SecuritySeverity): number {
    switch (severity) {
      case SecuritySeverity.CRITICAL:
        return 4;
      case SecuritySeverity.HIGH:
        return 3;
      case SecuritySeverity.MEDIUM:
        return 2;
      case SecuritySeverity.LOW:
      default:
        return 1;
    }
  }
}