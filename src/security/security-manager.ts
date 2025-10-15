/**
 * Security Manager for Logixia
 * 
 * Coordinates encryption, PII detection, audit trail, access control,
 * data loss prevention, and security monitoring features
 */

import { 
  SecurityConfig, 
  EncryptionConfig, 
  PIIConfig, 
  AuditConfig,
  AccessControlConfig,
  SecurityEventType,
  SecuritySeverity
} from '../types/security.types';
import { 
  EncryptionEngine, 
  IEncryptionEngine, 
  IFieldEncryption 
} from './encryption.engine';
import { 
  PIIDetector, 
  IPIIDetector, 
  ComplianceConfig, 
  ComplianceViolation 
} from './pii-detector';
import { 
  AuditTrail, 
  IAuditTrail, 
  TamperDetectionOptions, 
  AuditReport, 
  AuditAnomaly 
} from './audit-trail';
import {
  DLPEngine,
  IDLPEngine,
  DLPRule,
  QuarantinedEntry
} from './dlp-engine';
import {
  SecurityMonitoring,
  ISecurityMonitoring,
  SecurityRule,
  SecurityIncident
} from './security-monitoring';
import { LogEntry } from '../types';

/**
 * Data Loss Prevention configuration
 */
export interface DLPConfig {
  enabled: boolean;
  scanContent?: boolean;
  enforcePolicy?: boolean;
  quarantineEnabled?: boolean;
  quarantineThreshold?: number; // 0-1 value
  alertOnViolation?: boolean;
  violationHandler?: (violation: DLPViolation) => Promise<void>;
}

/**
 * Data Loss Prevention violation
 */
export interface DLPViolation {
  type: 'sensitive_content' | 'policy_violation' | 'data_leak';
  description: string;
  severity: SecuritySeverity;
  content: string;
  timestamp: Date;
  logEntryId?: string;
  metadata?: Record<string, any>;
}

/**
 * Security monitoring configuration
 */
export interface SecurityMonitoringConfig {
  enabled: boolean;
  realTimeAlerts?: boolean;
  anomalyDetection?: boolean;
  anomalyThreshold?: number; // 0-1 value
  alertHandler?: (alert: SecurityAlert) => Promise<void>;
}

/**
 * Security alert
 */
export interface SecurityAlert {
  type: 'threat' | 'anomaly' | 'policy_violation' | 'tamper';
  description: string;
  severity: SecuritySeverity;
  timestamp: Date;
  source: string;
  metadata?: Record<string, any>;
}

/**
 * Interface for security manager
 */
export interface ISecurityManager {
  processLogEntry(entry: LogEntry): Promise<LogEntry>;
  encryptField(fieldName: string, value: any): Promise<any>;
  decryptField(fieldName: string, value: any): Promise<any>;
  maskPII(text: string): Promise<string>;
  logAccess(userId: string, resource: string, action: string, metadata?: Record<string, any>): Promise<string>;
  logSecurityEvent(type: SecurityEventType, description: string, severity: SecuritySeverity, metadata?: Record<string, any>): Promise<string>;
  scanForSensitiveContent(content: string): Promise<DLPViolation[]>;
  generateAuditReport(startDate: Date, endDate: Date): Promise<AuditReport>;
  detectAnomalies(timeframe?: number): Promise<AuditAnomaly[]>;
  rotateEncryptionKey(keyId: string): Promise<string>;
  verifyAuditIntegrity(auditId: string): Promise<boolean>;
  getEncryptionEngine(): IEncryptionEngine | undefined;
  getFieldEncryption(): IFieldEncryption | undefined;
  getPIIDetector(): IPIIDetector | undefined;
  getAuditTrail(): IAuditTrail | undefined;
  getDLPEngine(): IDLPEngine | undefined;
  getSecurityMonitoring(): ISecurityMonitoring | undefined;
  isEnabled(): boolean;
  close(): Promise<void>;
}

/**
 * Default implementation of security manager
 */
export class SecurityManager implements ISecurityManager {
  private config: SecurityConfig;
  private encryptionEngine?: IEncryptionEngine;
  private piiDetector?: IPIIDetector;
  private auditTrail?: IAuditTrail;
  private dlpEngine?: IDLPEngine;
  private securityMonitoring?: ISecurityMonitoring;
  private userId: string = 'system';

  constructor(config?: SecurityConfig) {
    this.config = config || {};
    
    // Initialize encryption engine if configured
    if (this.config.encryption?.enabled) {
      this.encryptionEngine = new EncryptionEngine(this.config.encryption);
    }
    
    // Initialize PII detector if configured
    if (this.config.pii?.enabled) {
      this.piiDetector = new PIIDetector(this.config.pii);
      
      // Enable compliance framework if specified
      if (this.config.pii.complianceFramework) {
        const complianceConfig: ComplianceConfig = {
          framework: this.config.pii.complianceFramework as any,
          strictMode: this.config.pii.strictCompliance,
          reportViolations: true,
          violationHandler: async (violation) => {
            await this.handleComplianceViolation(violation);
          }
        };
        
        this.piiDetector.enableCompliance(complianceConfig);
      }
    }
    
    // Initialize audit trail if configured
    if (this.config.audit?.enabled) {
      this.auditTrail = new AuditTrail(this.config.audit);
      
      // Enable tamper detection if specified
      if (this.config.audit.tamperDetection) {
        const tamperOptions: TamperDetectionOptions = {
          enabled: true,
          signatureAlgorithm: 'hmac-sha256',
          verifyOnRead: true,
          alertOnTamper: true,
          tamperHandler: async (entry, error) => {
            await this.handleTamperDetection(entry, error);
          }
        };
        
        this.auditTrail.enableTamperDetection(tamperOptions);
      }
    }
    
    // Initialize DLP engine if configured
    if (this.config.dlp?.enabled) {
      this.dlpEngine = new DLPEngine(this.config.dlp, this.piiDetector);
    }
    
    // Initialize security monitoring if configured
    if (this.config.monitoring?.enabled) {
      this.securityMonitoring = new SecurityMonitoring(this.config.monitoring, this.auditTrail);
    }
    
    // Log security manager initialization
    this.logSecurityEvent(
      SecurityEventType.CONFIGURATION_CHANGE,
      'Security manager initialized',
      SecuritySeverity.LOW,
      { features: this.getEnabledFeatures() }
    ).catch(err => {
      console.error('Failed to log security manager initialization:', err);
    });
  }
  
  /**
   * Get enabled security features
   */
  private getEnabledFeatures(): string[] {
    const features: string[] = [];
    
    if (this.encryptionEngine?.isEnabled()) {
      features.push('encryption');
    }
    
    if (this.piiDetector?.isEnabled()) {
      features.push('pii_detection');
    }
    
    if (this.auditTrail?.isEnabled()) {
      features.push('audit_trail');
    }
    
    if (this.dlpEngine?.isEnabled()) {
      features.push('dlp');
    }
    
    if (this.securityMonitoring?.isEnabled()) {
      features.push('security_monitoring');
    }
    
    return features;
  }

  /**
   * Check if security features are enabled
   */
  isEnabled(): boolean {
    return !!(this.encryptionEngine || this.piiDetector || this.auditTrail || 
              this.dlpEngine || this.securityMonitoring);
  }

  /**
   * Get the encryption engine
   */
  getEncryptionEngine(): IEncryptionEngine | undefined {
    return this.encryptionEngine;
  }

  /**
   * Get the field encryption
   */
  getFieldEncryption(): IFieldEncryption | undefined {
    return this.encryptionEngine?.getFieldEncryption();
  }

  /**
   * Get the PII detector
   */
  getPIIDetector(): IPIIDetector | undefined {
    return this.piiDetector;
  }

  /**
   * Get the audit trail
   */
  getAuditTrail(): IAuditTrail | undefined {
    return this.auditTrail;
  }
  
  /**
   * Get the DLP engine
   */
  getDLPEngine(): IDLPEngine | undefined {
    return this.dlpEngine;
  }
  
  /**
   * Get the security monitoring engine
   */
  getSecurityMonitoring(): ISecurityMonitoring | undefined {
    return this.securityMonitoring;
  }

  /**
   * Process a log entry with all security features
   * @param entry Log entry to process
   * @returns Processed log entry
   */
  async processLogEntry(entry: LogEntry): Promise<LogEntry> {
    if (!this.isEnabled()) {
      return entry;
    }
    
    let processedEntry = { ...entry };
    
    // Apply encryption if enabled
    if (this.encryptionEngine?.isEnabled() && this.config.encryption?.fields?.length) {
      processedEntry = await this.processEncryption(processedEntry);
    }
    
    // Apply PII detection if enabled
    if (this.piiDetector?.isEnabled()) {
      processedEntry = await this.processPII(processedEntry);
    }
    
    // Apply DLP if enabled
    if (this.dlpEngine?.isEnabled()) {
      processedEntry = await this.processDLP(processedEntry);
    }
    
    // Log to audit trail if enabled
    if (this.auditTrail?.isEnabled()) {
      const auditId = await this.auditTrail.logAccess(
        this.userId, // Use configured user ID
        'log_entry',
        'create',
        { level: entry.level }
      );
      
      if (auditId) {
        processedEntry.auditId = auditId;
      }
    }
    
    // Apply security monitoring if enabled
    if (this.securityMonitoring?.isEnabled()) {
      await this.processSecurityMonitoring(processedEntry);
    }
    
    return processedEntry;
  }

  /**
   * Process encryption for a log entry
   * @param entry Log entry to encrypt
   * @returns Encrypted log entry
   */
  private async processEncryption(entry: LogEntry): Promise<LogEntry> {
    if (!this.encryptionEngine || !this.config.encryption?.fields) {
      return entry;
    }
    
    const encryptedFields: Record<string, any> = {};
    const processedEntry = { ...entry };
    const fieldEncryption = this.encryptionEngine.getFieldEncryption();
    
    // Process payload fields
    if (processedEntry.payload) {
      for (const field of this.config.encryption.fields) {
        if (processedEntry.payload[field] !== undefined) {
          try {
            const encrypted = await fieldEncryption.encryptField(
              field,
              processedEntry.payload[field]
            );
            
            encryptedFields[field] = encrypted;
            delete processedEntry.payload[field];
          } catch (error) {
            console.error(`Failed to encrypt field ${field}:`, error);
            
            // Log encryption failure
            this.logSecurityEvent(
              SecurityEventType.SECURITY_VIOLATION,
              `Failed to encrypt field ${field}`,
              SecuritySeverity.MEDIUM,
              { error: error.message, field }
            ).catch(err => {
              console.error('Failed to log encryption failure:', err);
            });
          }
        }
      }
    }
    
    // Add encrypted fields to the entry
    if (Object.keys(encryptedFields).length > 0) {
      processedEntry.encryptedFields = encryptedFields;
    }
    
    return processedEntry;
  }

  /**
   * Process PII detection for a log entry
   * @param entry Log entry to process
   * @returns Processed log entry
   */
  private async processPII(entry: LogEntry): Promise<LogEntry> {
    if (!this.piiDetector) {
      return entry;
    }
    
    const processedEntry = { ...entry };
    let piiDetected = false;
    
    // Process message
    if (processedEntry.message) {
      const originalMessage = processedEntry.message;
      processedEntry.message = await this.piiDetector.mask(processedEntry.message);
      
      if (processedEntry.message !== originalMessage) {
        piiDetected = true;
      }
    }
    
    // Process payload fields
    if (processedEntry.payload) {
      const newPayload: Record<string, any> = {};
      
      for (const [key, value] of Object.entries(processedEntry.payload)) {
        if (typeof value === 'string') {
          const maskedValue = await this.piiDetector.mask(value);
          newPayload[key] = maskedValue;
          
          if (maskedValue !== value) {
            piiDetected = true;
          }
        } else if (typeof value === 'object' && value !== null) {
          // Handle nested objects by converting to string and back
          try {
            const jsonString = JSON.stringify(value);
            const maskedJson = await this.piiDetector.mask(jsonString);
            
            if (maskedJson !== jsonString) {
              piiDetected = true;
              newPayload[key] = JSON.parse(maskedJson);
            } else {
              newPayload[key] = value;
            }
          } catch (error) {
            console.error(`Failed to process nested object in field ${key}:`, error);
            newPayload[key] = value;
          }
        } else {
          newPayload[key] = value;
        }
      }
      
      processedEntry.payload = newPayload;
    }
    
    if (piiDetected) {
      processedEntry.piiDetected = true;
      
      // Log PII detection
      this.logSecurityEvent(
        SecurityEventType.SECURITY_VIOLATION,
        'PII detected and masked in log entry',
        SecuritySeverity.MEDIUM,
        { logId: entry.auditId || 'unknown' }
      ).catch(err => {
        console.error('Failed to log PII detection:', err);
      });
    }
    
    return processedEntry;
  }

  /**
   * Process DLP for a log entry
   * @param entry Log entry to process
   * @returns Processed log entry
   */
  private async processDLP(entry: LogEntry): Promise<LogEntry> {
    if (!this.dlpConfig?.enabled || !this.dlpConfig.scanContent) {
      return entry;
    }
    
    const processedEntry = { ...entry };
    
    // Scan message and payload for sensitive content
    const contentToScan: string[] = [];
    
    if (processedEntry.message) {
      contentToScan.push(processedEntry.message);
    }
    
    if (processedEntry.payload) {
      try {
        contentToScan.push(JSON.stringify(processedEntry.payload));
      } catch (error) {
        console.error('Failed to stringify payload for DLP scanning:', error);
      }
    }
    
    // Combine content for scanning
    const fullContent = contentToScan.join(' ');
    
    // Scan for sensitive content
    const violations = await this.scanForSensitiveContent(fullContent);
    
    if (violations.length > 0) {
      // Check if any violations exceed quarantine threshold
      const shouldQuarantine = this.dlpConfig.quarantineEnabled && 
        violations.some(v => 
          v.severity === SecuritySeverity.CRITICAL || 
          (v.metadata?.score && v.metadata.score >= this.dlpConfig.quarantineThreshold!)
        );
      
      if (shouldQuarantine) {
        // Quarantine the log entry
        processedEntry.quarantined = true;
        
        // Store original content securely
        if (!processedEntry.metadata) {
          processedEntry.metadata = {};
        }
        
        // Encrypt the quarantined content if encryption is enabled
        if (this.encryptionEngine?.isEnabled()) {
          try {
            const encryptedContent = await this.encryptionEngine.encrypt(fullContent);
            processedEntry.metadata.quarantinedContent = encryptedContent;
          } catch (error) {
            console.error('Failed to encrypt quarantined content:', error);
            processedEntry.metadata.quarantineError = 'Failed to secure quarantined content';
          }
        } else {
          // Just mark as quarantined without storing the content
          processedEntry.metadata.quarantineReason = violations[0].description;
        }
        
        // Replace sensitive content with placeholder
        processedEntry.message = '[Content quarantined due to security policy]';
        processedEntry.payload = { 
          _quarantined: true, 
          _reason: violations[0].description 
        };
        
        // Log quarantine action
        this.logSecurityEvent(
          SecurityEventType.SECURITY_VIOLATION,
          'Log entry quarantined due to DLP violation',
          SecuritySeverity.HIGH,
          { 
            logId: entry.auditId || 'unknown',
            violations: violations.map(v => ({ type: v.type, description: v.description }))
          }
        ).catch(err => {
          console.error('Failed to log quarantine action:', err);
        });
      } else {
        // Just mark the entry as containing sensitive content
        if (!processedEntry.metadata) {
          processedEntry.metadata = {};
        }
        processedEntry.metadata.dlpViolations = violations.map(v => ({
          type: v.type,
          description: v.description,
          severity: v.severity
        }));
      }
    }
    
    return processedEntry;
  }

  /**
   * Encrypt a field
   * @param fieldName Field name
   * @param value Field value
   * @returns Encrypted value
   */
  async encryptField(fieldName: string, value: any): Promise<any> {
    if (!this.encryptionEngine) {
      return value;
    }
    
    try {
      const fieldEncryption = this.encryptionEngine.getFieldEncryption();
      return await fieldEncryption.encryptField(fieldName, value);
    } catch (error) {
      console.error(`Failed to encrypt field ${fieldName}:`, error);
      
      // Log encryption failure
      this.logSecurityEvent(
        SecurityEventType.SECURITY_VIOLATION,
        `Failed to encrypt field ${fieldName}`,
        SecuritySeverity.MEDIUM,
        { error: error.message, field: fieldName }
      ).catch(err => {
        console.error('Failed to log encryption failure:', err);
      });
      
      return value;
    }
  }

  /**
   * Decrypt a field
   * @param fieldName Field name
   * @param value Encrypted value
   * @returns Decrypted value
   */
  async decryptField(fieldName: string, value: any): Promise<any> {
    if (!this.encryptionEngine) {
      return value;
    }
    
    try {
      const fieldEncryption = this.encryptionEngine.getFieldEncryption();
      return await fieldEncryption.decryptField(fieldName, value);
    } catch (error) {
      console.error(`Failed to decrypt field ${fieldName}:`, error);
      
      // Log decryption failure
      this.logSecurityEvent(
        SecurityEventType.SECURITY_VIOLATION,
        `Failed to decrypt field ${fieldName}`,
        SecuritySeverity.MEDIUM,
        { error: error.message, field: fieldName }
      ).catch(err => {
        console.error('Failed to log decryption failure:', err);
      });
      
      return value;
    }
  }

  /**
   * Mask PII in text
   * @param text Text to mask
   * @returns Masked text
   */
  async maskPII(text: string): Promise<string> {
    if (!this.piiDetector) {
      return text;
    }
    
    return await this.piiDetector.mask(text);
  }

  /**
   * Log access to a resource
   * @param userId User ID
   * @param resource Resource being accessed
   * @param action Action being performed
   * @param metadata Additional metadata
   * @returns Audit entry ID
   */
  async logAccess(userId: string, resource: string, action: string, metadata?: Record<string, any>): Promise<string> {
    if (!this.auditTrail) {
      return '';
    }
    
    return await this.auditTrail.logAccess(userId, resource, action, metadata);
  }

  /**
   * Log a security event
   * @param type Event type
   * @param description Event description
   * @param severity Event severity
   * @param metadata Additional metadata
   * @returns Audit entry ID
   */
  async logSecurityEvent(type: SecurityEventType, description: string, severity: SecuritySeverity, metadata?: Record<string, any>): Promise<string> {
    if (!this.auditTrail) {
      return '';
    }
    
    const event = {
      type,
      severity,
      description,
      metadata: metadata || {},
      timestamp: new Date(),
      userId: this.userId
    };
    
    return await this.auditTrail.logSecurityEvent(event);
  }

  /**
   * Scan for sensitive content
   * @param content Content to scan
   * @returns Array of DLP violations
   */
  async scanForSensitiveContent(content: string): Promise<DLPViolation[]> {
    if (!this.dlpConfig?.enabled || !this.dlpConfig.scanContent || !content) {
      return [];
    }
    
    const violations: DLPViolation[] = [];
    
    // Use PII detector to find sensitive information
    if (this.piiDetector?.isEnabled()) {
      const piiMatches = await this.piiDetector.detect(content);
      
      // Group matches by type
      const matchesByType = new Map<string, number>();
      for (const match of piiMatches) {
        const count = matchesByType.get(match.type) || 0;
        matchesByType.set(match.type, count + 1);
      }
      
      // Create violations for each type of PII
      for (const [type, count] of matchesByType.entries()) {
        let severity: SecuritySeverity;
        
        // Determine severity based on PII type and count
        if (type === PIIType.CREDIT_CARD || type === PIIType.SSN) {
          severity = SecuritySeverity.CRITICAL;
        } else if (type === PIIType.PASSPORT || type === PIIType.DRIVERS_LICENSE) {
          severity = SecuritySeverity.HIGH;
        } else if (count > 3) {
          severity = SecuritySeverity.HIGH;
        } else {
          severity = SecuritySeverity.MEDIUM;
        }
        
        violations.push({
          type: 'sensitive_content',
          description: `Detected ${count} instances of ${type} in content`,
          severity,
          content: content.substring(0, 100) + '...',
          timestamp: new Date(),
          metadata: {
            piiType: type,
            count,
            score: count > 5 ? 0.9 : count > 2 ? 0.7 : 0.5
          }
        });
      }
    }
    
    // Check for specific policy violations
    // This is a simplified implementation - in a real system, this would be more comprehensive
    if (content.toLowerCase().includes('password') || content.toLowerCase().includes('secret')) {
      violations.push({
        type: 'policy_violation',
        description: 'Potential credential exposure in log content',
        severity: SecuritySeverity.HIGH,
        content: content.substring(0, 100) + '...',
        timestamp: new Date(),
        metadata: {
          score: 0.85
        }
      });
    }
    
    // Handle DLP violations
    if (violations.length > 0 && this.dlpConfig.alertOnViolation && this.dlpConfig.violationHandler) {
      for (const violation of violations) {
        try {
          await this.dlpConfig.violationHandler(violation);
        } catch (error) {
          console.error('Failed to handle DLP violation:', error);
        }
      }
    }
    
    return violations;
  }

  /**
   * Generate an audit report
   * @param startDate Start date
   * @param endDate End date
   * @returns Audit report
   */
  async generateAuditReport(startDate: Date, endDate: Date): Promise<AuditReport> {
    if (!this.auditTrail) {
      throw new Error('Audit trail is not enabled');
    }
    
    return await this.auditTrail.generateReport({
      startDate,
      endDate
    });
  }

  /**
   * Detect anomalies in audit logs
   * @param timeframe Timeframe in hours
   * @returns Array of anomalies
   */
  async detectAnomalies(timeframe?: number): Promise<AuditAnomaly[]> {
    if (!this.auditTrail) {
      throw new Error('Audit trail is not enabled');
    }
    
    return await this.auditTrail.detectAnomalies(timeframe);
  }

  /**
   * Rotate an encryption key
   * @param keyId Key ID to rotate
   * @returns New key ID
   */
  async rotateEncryptionKey(keyId: string): Promise<string> {
    if (!this.encryptionEngine) {
      throw new Error('Encryption is not enabled');
    }
    
    const newKeyId = await this.encryptionEngine.rotateKey(keyId);
    
    // Log key rotation
    await this.logSecurityEvent(
      SecurityEventType.KEY_ROTATION,
      `Encryption key rotated: ${keyId} -> ${newKeyId}`,
      SecuritySeverity.MEDIUM,
      { oldKeyId: keyId, newKeyId }
    );
    
    return newKeyId;
  }

  /**
   * Verify the integrity of an audit entry
   * @param auditId Audit entry ID
   * @returns True if the entry is valid
   */
  async verifyAuditIntegrity(auditId: string): Promise<boolean> {
    if (!this.auditTrail) {
      throw new Error('Audit trail is not enabled');
    }
    
    return await this.auditTrail.verifyIntegrity(auditId);
  }

  /**
   * Handle a compliance violation
   * @param violation Compliance violation
   */
  private async handleComplianceViolation(violation: ComplianceViolation): Promise<void> {
    // Log the violation
    await this.logSecurityEvent(
      SecurityEventType.SECURITY_VIOLATION,
      `Compliance violation: ${violation.framework} - ${violation.rule}`,
      violation.severity as SecuritySeverity,
      {
        framework: violation.framework,
        rule: violation.rule,
        description: violation.description,
        matchCount: violation.matches.length
      }
    );
    
    // Additional handling could be implemented here
    // For example, sending alerts, triggering remediation workflows, etc.
  }

  /**
   * Handle tamper detection
   * @param entry Tampered audit entry
   * @param error Error message
   */
  private async handleTamperDetection(entry: AuditEntry, error: string): Promise<void> {
    // Log the tamper detection
    await this.logSecurityEvent(
      SecurityEventType.SECURITY_VIOLATION,
      `Audit log tampering detected: ${error}`,
      SecuritySeverity.CRITICAL,
      {
        auditId: entry.id,
        timestamp: entry.timestamp,
        userId: entry.userId,
        action: entry.action,
        resource: entry.resource
      }
    );
    
    // If security monitoring is enabled, create an alert
    if (this.securityMonitoringConfig?.enabled && this.securityMonitoringConfig.alertHandler) {
      const alert: SecurityAlert = {
        type: 'tamper',
        description: `Audit log tampering detected: ${error}`,
        severity: SecuritySeverity.CRITICAL,
        timestamp: new Date(),
        source: 'audit_trail',
        metadata: {
          auditId: entry.id,
          timestamp: entry.timestamp,
          userId: entry.userId,
          action: entry.action,
          resource: entry.resource
        }
      };
      
      try {
        await this.securityMonitoringConfig.alertHandler(alert);
      } catch (error) {
        console.error('Failed to handle tamper detection alert:', error);
      }
    }
  }

  /**
   * Handle a DLP violation
   * @param violation DLP violation
   */
  private async handleDLPViolation(violation: DLPViolation): Promise<void> {
    // Log the violation
    await this.logSecurityEvent(
      SecurityEventType.SECURITY_VIOLATION,
      `DLP violation: ${violation.description}`,
      violation.severity,
      {
        type: violation.type,
        timestamp: violation.timestamp,
        logEntryId: violation.logEntryId,
        ...violation.metadata
      }
    );
    
    // If security monitoring is enabled, create an alert
    if (this.securityMonitoringConfig?.enabled && this.securityMonitoringConfig.alertHandler) {
      const alert: SecurityAlert = {
        type: 'policy_violation',
        description: `DLP violation: ${violation.description}`,
        severity: violation.severity,
        timestamp: new Date(),
        source: 'dlp',
        metadata: {
          type: violation.type,
          logEntryId: violation.logEntryId,
          ...violation.metadata
        }
      };
      
      try {
        await this.securityMonitoringConfig.alertHandler(alert);
      } catch (error) {
        console.error('Failed to handle DLP violation alert:', error);
      }
    }
  }

  /**
   * Handle a security alert
   * @param alert Security alert
   */
  private async handleSecurityAlert(alert: SecurityAlert): Promise<void> {
    // Log the alert
    await this.logSecurityEvent(
      SecurityEventType.SECURITY_VIOLATION,
      `Security alert: ${alert.description}`,
      alert.severity,
      {
        type: alert.type,
        source: alert.source,
        timestamp: alert.timestamp,
        ...alert.metadata
      }
    );
    
    // Additional handling could be implemented here
    // For example, sending notifications, triggering incident response, etc.
  }

  /**
   * Close the security manager and release resources
   */
  async close(): Promise<void> {
    // Close audit trail
    if (this.auditTrail) {
      await this.auditTrail.close();
    }
    
    // Log security manager shutdown
    console.log('Security manager closed');
  }
}