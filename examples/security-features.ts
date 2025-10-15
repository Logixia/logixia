/**
 * Example demonstrating the comprehensive security features of Logixia
 * 
 * This example shows how to:
 * 1. Configure encryption for sensitive log data
 * 2. Set up PII detection and masking
 * 3. Enable audit trails for compliance
 * 4. Configure DLP (Data Loss Prevention)
 * 5. Set up security monitoring
 */

import { LogixiaLogger } from '../src';

// Create a logger with security features enabled
const logger = new LogixiaLogger({
  appName: 'SecureApp',
  environment: 'production',
  format: {
    json: true // Use JSON format for structured logging
  },
  // Configure comprehensive security features
  security: {
    // Field-level encryption
    encryption: {
      enabled: true,
      algorithm: 'aes-256-gcm',
      fields: ['password', 'creditCard', 'ssn', 'apiKey', 'token'],
      keyProvider: 'local' // In production, use 'vault', 'aws-kms', etc.
    },
    
    // PII detection and masking
    pii: {
      enabled: true,
      detectionTypes: ['EMAIL', 'PHONE', 'CREDIT_CARD', 'SSN', 'IP_ADDRESS', 'NAME', 'ADDRESS'],
      maskCharacter: '*',
      preserveLength: true,
      preserveFirstN: 2,
      preserveLastN: 2,
      confidenceThreshold: 0.7,
      complianceFramework: 'gdpr', // Enable GDPR compliance rules
      strictCompliance: true
    },
    
    // Comprehensive audit trails
    audit: {
      enabled: true,
      storage: 'file',
      storageConfig: {
        directory: './logs/audit',
        filename: 'security-audit.log'
      },
      logAccess: true,
      logChanges: true,
      logSecurityEvents: true,
      retentionPeriod: 90, // Days
      tamperDetection: true // Enable tamper detection for audit logs
    },
    
    // Data Loss Prevention
    dlp: {
      enabled: true,
      scanContent: true,
      enforcePolicy: true,
      quarantineEnabled: true,
      quarantineThreshold: 0.8,
      alertOnViolation: true
    },
    
    // Security monitoring
    monitoring: {
      enabled: true,
      realTimeAlerts: true,
      anomalyDetection: true,
      anomalyThreshold: 0.7
    }
  }
});

// Example 1: Logging with automatic PII detection and masking
logger.info('User profile updated', {
  user: 'john.doe@example.com',
  phone: '555-123-4567',
  address: '123 Main St, Anytown, USA',
  lastLogin: new Date()
});
// Output will mask the email, phone, and address

// Example 2: Explicitly encrypting sensitive fields
async function logSensitiveData() {
  const userData = {
    username: 'johndoe',
    password: 'SecureP@ssw0rd!',
    creditCard: '4111-1111-1111-1111',
    ssn: '123-45-6789'
  };
  
  // Log with automatic field encryption
  await logger.info('User payment processed', userData);
  // The password, creditCard, and ssn fields will be encrypted
}

// Example 3: Using the security manager directly
async function useSecurityManager() {
  const securityManager = logger.getSecurityManager();
  
  if (securityManager) {
    // Encrypt a specific field
    const encryptedValue = await securityManager.encryptField('apiKey', 'sk_test_abcdefghijklmnopqrstuvwxyz');
    
    // Mask PII in text
    const maskedText = await securityManager.maskPII('Contact John Doe at john.doe@example.com or 555-123-4567');
    
    // Log access to a resource
    await securityManager.logAccess('user123', 'customer_record', 'view', { recordId: '12345' });
    
    // Log a security event
    await securityManager.logSecurityEvent(
      'SECURITY_VIOLATION',
      'Failed login attempt',
      'HIGH',
      { username: 'admin', ipAddress: '192.168.1.1', attempts: 5 }
    );
    
    // Scan for sensitive content
    const violations = await securityManager.scanForSensitiveContent(
      'The password is SecureP@ssw0rd! and the API key is sk_test_abcdefghijklmnopqrstuvwxyz'
    );
    
    // Generate an audit report
    const report = await securityManager.generateAuditReport(
      new Date(Date.now() - 7 * 24 * 60 * 60 * 1000), // 7 days ago
      new Date()
    );
    
    // Detect anomalies
    const anomalies = await securityManager.detectAnomalies(24); // Last 24 hours
    
    // Rotate encryption key
    const newKeyId = await securityManager.rotateEncryptionKey('old-key-id');
    
    // Verify audit integrity
    const isValid = await securityManager.verifyAuditIntegrity('audit-entry-id');
  }
}

// Run the examples
logSensitiveData().catch(console.error);
useSecurityManager().catch(console.error);

// Clean up
logger.close().catch(console.error);