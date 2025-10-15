/**
 * Security-related type definitions for Logixia
 */

// Encryption types
export enum EncryptionAlgorithm {
  AES_256_GCM = 'aes-256-gcm',
  CHACHA20_POLY1305 = 'chacha20-poly1305',
  RSA_OAEP = 'rsa-oaep'
}

export interface EncryptionConfig {
  enabled: boolean;
  algorithm?: EncryptionAlgorithm;
  keyId?: string;
  keyProvider?: 'local' | 'vault' | 'aws-kms' | 'azure-keyvault' | 'gcp-kms';
  keyProviderConfig?: Record<string, any>;
  fields?: string[]; // Fields to encrypt
}

export interface EncryptedData {
  algorithm: EncryptionAlgorithm;
  iv: string; // Initialization vector (base64)
  data: string; // Encrypted data (base64)
  keyId?: string; // Reference to the key used
  tag?: string; // Authentication tag for GCM mode (base64)
}

// PII Detection types
export enum PIIType {
  EMAIL = 'email',
  PHONE = 'phone',
  SSN = 'ssn',
  CREDIT_CARD = 'credit_card',
  IP_ADDRESS = 'ip_address',
  NAME = 'name',
  ADDRESS = 'address',
  PASSPORT = 'passport',
  DRIVERS_LICENSE = 'drivers_license',
  CUSTOM = 'custom'
}

export interface PIIMatch {
  type: PIIType;
  value: string;
  confidence: number;
  startIndex: number;
  endIndex: number;
}

export interface PIIRule {
  type: PIIType | string;
  pattern: RegExp | string;
  description?: string;
  confidence?: number; // 0-1 value
}

export interface PIIConfig {
  enabled: boolean;
  detectionTypes?: PIIType[];
  customRules?: PIIRule[];
  maskCharacter?: string;
  preserveLength?: boolean;
  preserveFirstN?: number;
  preserveLastN?: number;
  whitelistFields?: string[];
  blacklistFields?: string[];
  confidenceThreshold?: number; // 0-1 value
}

// Audit Trail types
export enum SecurityEventType {
  LOG_ACCESS = 'log_access',
  LOG_MODIFICATION = 'log_modification',
  CONFIGURATION_CHANGE = 'configuration_change',
  AUTHENTICATION = 'authentication',
  AUTHORIZATION = 'authorization',
  KEY_ROTATION = 'key_rotation',
  SECURITY_VIOLATION = 'security_violation'
}

export enum SecuritySeverity {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export interface SecurityEvent {
  type: SecurityEventType;
  severity: SecuritySeverity;
  description: string;
  metadata: Record<string, any>;
  timestamp: Date;
  userId?: string;
  resourceId?: string;
  sourceIp?: string;
  success?: boolean;
}

export interface AuditEntry {
  id: string;
  timestamp: Date;
  userId?: string;
  action: string;
  resource: string;
  resourceId?: string;
  oldValue?: any;
  newValue?: any;
  sourceIp?: string;
  userAgent?: string;
  success: boolean;
  metadata?: Record<string, any>;
}

export interface AuditQuery {
  startDate?: Date;
  endDate?: Date;
  userId?: string;
  action?: string | string[];
  resource?: string | string[];
  resourceId?: string;
  success?: boolean;
  limit?: number;
  offset?: number;
  sortBy?: string;
  sortDirection?: 'asc' | 'desc';
}

export interface AuditConfig {
  enabled: boolean;
  storage?: 'memory' | 'file' | 'database';
  storageConfig?: Record<string, any>;
  logAccess?: boolean;
  logChanges?: boolean;
  logSecurityEvents?: boolean;
  retentionPeriod?: number; // Days
}

// Access Control types
export interface AccessControlConfig {
  enabled: boolean;
  rbac?: boolean;
  roles?: Record<string, string[]>;
  ipWhitelist?: string[];
  mfaRequired?: boolean;
  sessionTimeout?: number; // Minutes
}

// Data Loss Prevention Configuration
export interface DLPConfig {
  enabled: boolean;
  scanContent?: boolean;
  enforcePolicy?: boolean;
  quarantineEnabled?: boolean;
  quarantineThreshold?: number; // 0-1 value
  alertOnViolation?: boolean;
}

// Security Monitoring Configuration
export interface SecurityMonitoringConfig {
  enabled: boolean;
  realTimeAlerts?: boolean;
  anomalyDetection?: boolean;
  anomalyThreshold?: number; // 0-1 value
}

// Combined Security Configuration
export interface SecurityConfig {
  encryption?: EncryptionConfig;
  pii?: PIIConfig & {
    complianceFramework?: 'gdpr' | 'hipaa' | 'ccpa' | 'pci-dss';
    strictCompliance?: boolean;
  };
  audit?: AuditConfig & {
    tamperDetection?: boolean;
  };
  accessControl?: AccessControlConfig;
  dlp?: DLPConfig;
  monitoring?: SecurityMonitoringConfig;
}