/**
 * PII Detection Engine for Logixia
 * 
 * Detects and masks personally identifiable information (PII) in log data
 * Supports pattern-based detection, ML models, and compliance frameworks
 */

import { PIIConfig, PIIMatch, PIIRule, PIIType } from '../types/security.types';

/**
 * ML model data for PII detection
 */
export interface MLModelData {
  modelType: 'tensorflow' | 'onnx' | 'custom';
  modelUrl?: string;
  modelBuffer?: Buffer;
  labels?: string[];
  threshold?: number;
  metadata?: Record<string, any>;
}

/**
 * Compliance framework configuration
 */
export interface ComplianceConfig {
  framework: 'gdpr' | 'hipaa' | 'ccpa' | 'pci-dss' | 'custom';
  strictMode?: boolean;
  customRules?: PIIRule[];
  reportViolations?: boolean;
  violationHandler?: (violation: ComplianceViolation) => Promise<void>;
}

/**
 * Compliance violation
 */
export interface ComplianceViolation {
  framework: string;
  rule: string;
  description: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  matches: PIIMatch[];
  timestamp: Date;
  context?: Record<string, any>;
}

/**
 * Interface for PII detection engine
 */
export interface IPIIDetector {
  detect(text: string): Promise<PIIMatch[]>;
  mask(text: string, matches?: PIIMatch[]): Promise<string>;
  addCustomRule(rule: PIIRule): void;
  updateModel(modelData: MLModelData): Promise<void>;
  enableCompliance(config: ComplianceConfig): void;
  isEnabled(): boolean;
}

/**
 * Default implementation of PII detection engine
 */
export class PIIDetector implements IPIIDetector {
  private config: PIIConfig;
  private rules: PIIRule[] = [];
  private mlModel?: MLModelData;
  private complianceConfig?: ComplianceConfig;

  constructor(config: PIIConfig) {
    this.config = config || { enabled: false };
    
    // Initialize default rules if enabled
    if (this.config.enabled) {
      this.initializeDefaultRules();
    }
    
    // Add custom rules if provided
    if (this.config.customRules && this.config.customRules.length > 0) {
      this.config.customRules.forEach(rule => this.addCustomRule(rule));
    }
  }

  /**
   * Update ML model for PII detection
   * @param modelData ML model data
   */
  async updateModel(modelData: MLModelData): Promise<void> {
    this.mlModel = modelData;
    
    // In a real implementation, we would load and initialize the ML model here
    console.log(`ML model updated: ${modelData.modelType}`);
  }

  /**
   * Enable compliance framework
   * @param config Compliance framework configuration
   */
  enableCompliance(config: ComplianceConfig): void {
    this.complianceConfig = config;
    
    // Add framework-specific rules
    if (config.framework === 'gdpr') {
      this.addGDPRRules();
    } else if (config.framework === 'hipaa') {
      this.addHIPAARules();
    } else if (config.framework === 'ccpa') {
      this.addCCPARules();
    } else if (config.framework === 'pci-dss') {
      this.addPCIDSSRules();
    }
    
    // Add custom compliance rules if provided
    if (config.customRules && config.customRules.length > 0) {
      config.customRules.forEach(rule => this.addCustomRule(rule));
    }
  }

  /**
   * Add GDPR-specific rules
   */
  private addGDPRRules(): void {
    // National ID numbers for EU countries
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b[A-Z]{2}[0-9]{6}[A-Z0-9]{1}\b/g, // Generic EU ID format
      description: 'EU National ID',
      confidence: 0.9
    });
    
    // EU VAT numbers
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b[A-Z]{2}[0-9]{8,12}\b/g,
      description: 'EU VAT Number',
      confidence: 0.8
    });
    
    // IBAN (International Bank Account Number)
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}([A-Z0-9]?){0,16}\b/g,
      description: 'IBAN',
      confidence: 0.9
    });
    
    // More comprehensive name detection
    this.addRule({
      type: PIIType.NAME,
      pattern: /\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+){1,3}\b/g,
      description: 'Full Name',
      confidence: 0.7
    });
  }

  /**
   * Add HIPAA-specific rules
   */
  private addHIPAARules(): void {
    // Medical record numbers
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\bMRN:?\s*[0-9]{6,10}\b/gi,
      description: 'Medical Record Number',
      confidence: 0.9
    });
    
    // Health insurance numbers
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b[A-Z]{1,2}[0-9]{6,12}\b/g,
      description: 'Health Insurance Number',
      confidence: 0.8
    });
    
    // Dates in healthcare context
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b(?:DOB|Date\s+of\s+Birth)[:=\s]+\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b/gi,
      description: 'Date of Birth',
      confidence: 0.95
    });
  }

  /**
   * Add CCPA-specific rules
   */
  private addCCPARules(): void {
    // California Driver's License
    this.addRule({
      type: PIIType.DRIVERS_LICENSE,
      pattern: /\b[A-Z][0-9]{7}\b/g,
      description: 'California Driver\'s License',
      confidence: 0.9
    });
    
    // Biometric identifiers
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b(?:fingerprint|retina|iris|face|voice)\s+(?:scan|recognition|id|identifier|data)\b/gi,
      description: 'Biometric Identifier',
      confidence: 0.7
    });
  }

  /**
   * Add PCI-DSS-specific rules
   */
  private addPCIDSSRules(): void {
    // More comprehensive credit card detection
    this.addRule({
      type: PIIType.CREDIT_CARD,
      pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
      description: 'Credit Card Number',
      confidence: 0.95
    });
    
    // CVV codes
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b(?:CVV|CVC|CVV2|CVC2|CVN|CVD|CID):?\s*[0-9]{3,4}\b/gi,
      description: 'Card Verification Value',
      confidence: 0.9
    });
    
    // Expiration dates
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b(?:exp|expiry|expiration)(?:\.|\s|:)+[0-9]{1,2}[-/][0-9]{2,4}\b/gi,
      description: 'Card Expiration Date',
      confidence: 0.8
    });
  }

  /**
   * Check if PII detection is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled === true;
  }

  /**
   * Initialize default PII detection rules
   */
  private initializeDefaultRules(): void {
    // Email addresses - more comprehensive
    this.addRule({
      type: PIIType.EMAIL,
      pattern: /\b[A-Za-z0-9._%+-]{1,64}@(?:[A-Za-z0-9-]{1,63}\.){1,125}[A-Za-z]{2,63}\b/g,
      confidence: 0.95
    });
    
    // Phone numbers - international format
    this.addRule({
      type: PIIType.PHONE,
      pattern: /\b(?:\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b/g,
      confidence: 0.9
    });
    
    // US Social Security Numbers - with validation
    this.addRule({
      type: PIIType.SSN,
      pattern: /\b(?!000|666|9\d{2})([0-8]\d{2}|7([0-6]\d|7[012]))([-]?)(?!00)\d{2}\3(?!0000)\d{4}\b/g,
      confidence: 0.95
    });
    
    // Credit Card Numbers - with validation for major card types
    this.addRule({
      type: PIIType.CREDIT_CARD,
      pattern: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11})\b/g,
      confidence: 0.95
    });
    
    // Credit Card Numbers with separators
    this.addRule({
      type: PIIType.CREDIT_CARD,
      pattern: /\b(?:4[0-9]{3}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|5[1-5][0-9]{2}[-\s]?[0-9]{4}[-\s]?[0-9]{4}[-\s]?[0-9]{4}|3[47][0-9]{2}[-\s]?[0-9]{6}[-\s]?[0-9]{5})\b/g,
      confidence: 0.95
    });
    
    // IP Addresses - IPv4 and IPv6
    this.addRule({
      type: PIIType.IP_ADDRESS,
      pattern: /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g,
      confidence: 0.9
    });
    
    // IPv6 addresses
    this.addRule({
      type: PIIType.IP_ADDRESS,
      pattern: /\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b/g,
      confidence: 0.9
    });
    
    // Names - more comprehensive
    this.addRule({
      type: PIIType.NAME,
      pattern: /\b[A-Z][a-z]+(?:[-'\s][A-Z][a-z]+)*\s+[A-Z][a-z]+(?:[-'\s][A-Z][a-z]+)*\b/g,
      confidence: 0.8
    });
    
    // Addresses - more comprehensive
    this.addRule({
      type: PIIType.ADDRESS,
      pattern: /\b\d+\s+(?:[A-Za-z0-9.-]+\s+)*(?:Avenue|Lane|Road|Boulevard|Drive|Street|Ave|Dr|Rd|Blvd|Ln|St|Circle|Cir|Court|Ct|Place|Pl|Square|Sq|Terrace|Ter|Way)\.?(?:\s+(?:Apt|Apartment|Unit|#)\s*[A-Za-z0-9-]+)?\b/gi,
      confidence: 0.85
    });
    
    // ZIP/Postal codes
    this.addRule({
      type: PIIType.ADDRESS,
      pattern: /\b[0-9]{5}(?:-[0-9]{4})?\b/g, // US ZIP code
      confidence: 0.9
    });
    
    // Passport Numbers - international
    this.addRule({
      type: PIIType.PASSPORT,
      pattern: /\b[A-Z]{1,2}[0-9]{6,9}\b/g,
      confidence: 0.9
    });
    
    // US Passport specific
    this.addRule({
      type: PIIType.PASSPORT,
      pattern: /\b(?:US passport|passport number|passport #):?\s*[0-9]{9}\b/gi,
      confidence: 0.95
    });
    
    // Driver's License - various formats
    this.addRule({
      type: PIIType.DRIVERS_LICENSE,
      pattern: /\b[A-Z][0-9]{7}\b/g, // CA format
      confidence: 0.9
    });
    
    this.addRule({
      type: PIIType.DRIVERS_LICENSE,
      pattern: /\b[0-9]{9}\b/g, // NY format
      confidence: 0.7 // Lower confidence due to potential false positives
    });
    
    // Date of Birth
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b(?:DOB|Date\s+of\s+Birth|Birth\s+Date)[:=\s]+\d{1,2}[-/]\d{1,2}[-/]\d{2,4}\b/gi,
      confidence: 0.9
    });
    
    // Bank account numbers
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b(?:bank\s+account|account\s+number|account\s+#)[:=\s]+[0-9]{8,17}\b/gi,
      confidence: 0.85
    });
    
    // JWT tokens
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\beyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+\b/g,
      confidence: 0.95
    });
    
    // API keys and access tokens
    this.addRule({
      type: PIIType.CUSTOM,
      pattern: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token)[:=\s]+[A-Za-z0-9_\-\.]{32,}\b/gi,
      confidence: 0.9
    });
  }

  /**
   * Add a rule to the PII detection engine
   * @param rule Rule to add
   */
  private addRule(rule: PIIRule): void {
    // Convert string patterns to RegExp if needed
    if (typeof rule.pattern === 'string') {
      rule.pattern = new RegExp(rule.pattern, 'g');
    }
    
    this.rules.push(rule);
  }

  /**
   * Add a custom rule to the PII detection engine
   * @param rule Custom rule to add
   */
  addCustomRule(rule: PIIRule): void {
    this.addRule(rule);
  }

  /**
   * Detect PII in text
   * @param text Text to analyze
   * @returns Array of PII matches
   */
  async detect(text: string): Promise<PIIMatch[]> {
    if (!this.isEnabled() || !text) {
      return [];
    }
    
    const matches: PIIMatch[] = [];
    const confidenceThreshold = this.config.confidenceThreshold || 0.7;
    
    // Apply pattern-based rules
    const patternMatches = await this.detectWithPatterns(text, confidenceThreshold);
    matches.push(...patternMatches);
    
    // Apply ML-based detection if configured
    if (this.mlModel) {
      const mlMatches = await this.detectWithML(text);
      matches.push(...mlMatches);
    }
    
    // Check for compliance violations if configured
    if (this.complianceConfig?.reportViolations && matches.length > 0) {
      await this.reportComplianceViolations(text, matches);
    }
    
    return matches;
  }
  
  /**
   * Detect PII using pattern-based rules
   * @param text Text to analyze
   * @param confidenceThreshold Minimum confidence threshold
   * @returns Array of PII matches
   */
  private async detectWithPatterns(text: string, confidenceThreshold: number): Promise<PIIMatch[]> {
    const matches: PIIMatch[] = [];
    
    // Apply each rule to the text
    for (const rule of this.rules) {
      // Skip if rule type is not in the enabled detection types
      if (this.config.detectionTypes && 
          !this.config.detectionTypes.includes(rule.type as PIIType)) {
        continue;
      }
      
      // Skip if confidence is below threshold
      if (rule.confidence && rule.confidence < confidenceThreshold) {
        continue;
      }
      
      const pattern = rule.pattern as RegExp;
      let match;
      
      // Reset the regex to start from the beginning
      pattern.lastIndex = 0;
      
      // Find all matches
      while ((match = pattern.exec(text)) !== null) {
        // Validate the match if needed (e.g., Luhn algorithm for credit cards)
        if (rule.type === PIIType.CREDIT_CARD && !this.validateCreditCard(match[0])) {
          continue;
        }
        
        matches.push({
          type: rule.type as PIIType,
          value: match[0],
          confidence: rule.confidence || 0.8,
          startIndex: match.index,
          endIndex: match.index + match[0].length
        });
      }
    }
    
    return matches;
  }
  
  /**
   * Detect PII using ML model
   * @param text Text to analyze
   * @returns Array of PII matches
   */
  private async detectWithML(text: string): Promise<PIIMatch[]> {
    if (!this.mlModel) {
      return [];
    }
    
    // This is a placeholder for ML-based detection
    // In a real implementation, we would use the ML model to detect PII
    console.log(`Using ${this.mlModel.modelType} model for PII detection`);
    
    // Simulate ML detection with a simple approach
    // In a real implementation, this would use TensorFlow.js, ONNX Runtime, or a custom ML solution
    const mlMatches: PIIMatch[] = [];
    const threshold = this.mlModel.threshold || 0.8;
    
    // Example: Detect potential names not caught by regex
    // This is a very simplified simulation of what an ML model might do
    const words = text.split(/\s+/);
    for (let i = 0; i < words.length; i++) {
      const word = words[i];
      
      // Check if word starts with capital letter and is not at the beginning of a sentence
      if (i > 0 && /^[A-Z][a-z]{2,}$/.test(word)) {
        // Check if previous word also matches the pattern (potential full name)
        if (/^[A-Z][a-z]{2,}$/.test(words[i-1])) {
          const fullName = `${words[i-1]} ${word}`;
          const startIndex = text.indexOf(fullName);
          
          // Only add if not already detected by pattern rules
          const isDuplicate = mlMatches.some(m => 
            m.type === PIIType.NAME && 
            m.startIndex <= startIndex && 
            m.endIndex >= startIndex + fullName.length
          );
          
          if (!isDuplicate) {
            mlMatches.push({
              type: PIIType.NAME,
              value: fullName,
              confidence: 0.85, // Simulated ML confidence
              startIndex,
              endIndex: startIndex + fullName.length
            });
          }
        }
      }
    }
    
    return mlMatches;
  }
  
  /**
   * Report compliance violations
   * @param text Original text
   * @param matches PII matches
   */
  private async reportComplianceViolations(text: string, matches: PIIMatch[]): Promise<void> {
    if (!this.complianceConfig || !this.complianceConfig.reportViolations) {
      return;
    }
    
    // Group matches by type
    const matchesByType = new Map<PIIType | string, PIIMatch[]>();
    for (const match of matches) {
      const type = match.type;
      if (!matchesByType.has(type)) {
        matchesByType.set(type, []);
      }
      matchesByType.get(type)!.push(match);
    }
    
    // Check for violations based on compliance framework
    const violations: ComplianceViolation[] = [];
    
    if (this.complianceConfig.framework === 'gdpr') {
      // Check for unencrypted personal data
      if (matchesByType.has(PIIType.NAME) || 
          matchesByType.has(PIIType.EMAIL) || 
          matchesByType.has(PIIType.ADDRESS)) {
        violations.push({
          framework: 'GDPR',
          rule: 'Article 32 - Security of processing',
          description: 'Personal data must be encrypted or pseudonymized',
          severity: 'high',
          matches: [...(matchesByType.get(PIIType.NAME) || []), 
                   ...(matchesByType.get(PIIType.EMAIL) || []),
                   ...(matchesByType.get(PIIType.ADDRESS) || [])],
          timestamp: new Date()
        });
      }
    } else if (this.complianceConfig.framework === 'hipaa') {
      // Check for unprotected health information
      if (matchesByType.has(PIIType.CUSTOM)) {
        const healthMatches = matchesByType.get(PIIType.CUSTOM)!.filter(m => 
          m.value.toLowerCase().includes('health') || 
          m.value.toLowerCase().includes('medical') ||
          m.value.toLowerCase().includes('patient')
        );
        
        if (healthMatches.length > 0) {
          violations.push({
            framework: 'HIPAA',
            rule: 'Security Rule - Technical Safeguards',
            description: 'Protected Health Information (PHI) must be secured',
            severity: 'critical',
            matches: healthMatches,
            timestamp: new Date()
          });
        }
      }
    } else if (this.complianceConfig.framework === 'pci-dss') {
      // Check for unprotected payment card data
      if (matchesByType.has(PIIType.CREDIT_CARD)) {
        violations.push({
          framework: 'PCI-DSS',
          rule: 'Requirement 3 - Protect stored cardholder data',
          description: 'Credit card information must be encrypted',
          severity: 'critical',
          matches: matchesByType.get(PIIType.CREDIT_CARD) || [],
          timestamp: new Date()
        });
      }
    }
    
    // Report violations
    if (violations.length > 0 && this.complianceConfig.violationHandler) {
      for (const violation of violations) {
        try {
          await this.complianceConfig.violationHandler(violation);
        } catch (error) {
          console.error('Failed to report compliance violation:', error);
        }
      }
    }
  }
  
  /**
   * Validate credit card number using Luhn algorithm
   * @param cardNumber Credit card number
   * @returns True if valid
   */
  private validateCreditCard(cardNumber: string): boolean {
    // Remove non-digit characters
    const digits = cardNumber.replace(/\D/g, '');
    
    // Check if length is valid
    if (digits.length < 13 || digits.length > 19) {
      return false;
    }
    
    // Luhn algorithm
    let sum = 0;
    let double = false;
    
    // Start from the rightmost digit and process each digit
    for (let i = digits.length - 1; i >= 0; i--) {
      let digit = parseInt(digits.charAt(i));
      
      if (double) {
        digit *= 2;
        if (digit > 9) {
          digit -= 9;
        }
      }
      
      sum += digit;
      double = !double;
    }
    
    // If sum is divisible by 10, the card number is valid
    return sum % 10 === 0;
  }

  /**
   * Mask PII in text
   * @param text Text to mask
   * @param matches Optional pre-detected matches
   * @returns Masked text
   */
  async mask(text: string, matches?: PIIMatch[]): Promise<string> {
    if (!this.isEnabled() || !text) {
      return text;
    }
    
    // Detect PII if matches not provided
    const piiMatches = matches || await this.detect(text);
    
    if (piiMatches.length === 0) {
      return text;
    }
    
    // Sort matches by start index in descending order to avoid index shifting
    const sortedMatches = [...piiMatches].sort((a, b) => b.startIndex - a.startIndex);
    
    let maskedText = text;
    const maskChar = this.config.maskCharacter || '*';
    const preserveLength = this.config.preserveLength !== false;
    const preserveFirstN = this.config.preserveFirstN || 0;
    const preserveLastN = this.config.preserveLastN || 0;
    
    // Apply masking to each match
    for (const match of sortedMatches) {
      const { value, startIndex, endIndex } = match;
      
      // Check if this field is in the whitelist
      if (this.config.whitelistFields && 
          this.isFieldWhitelisted(value, this.config.whitelistFields)) {
        continue;
      }
      
      // Check if this field is in the blacklist
      if (this.config.blacklistFields && 
          !this.isFieldBlacklisted(value, this.config.blacklistFields)) {
        continue;
      }
      
      // Create masked value
      let maskedValue: string;
      
      if (preserveFirstN > 0 || preserveLastN > 0) {
        // Preserve parts of the value
        const firstPart = value.substring(0, preserveFirstN);
        const lastPart = value.substring(value.length - preserveLastN);
        const middleLength = value.length - preserveFirstN - preserveLastN;
        
        if (middleLength > 0) {
          const middleMask = preserveLength ? maskChar.repeat(middleLength) : maskChar;
          maskedValue = firstPart + middleMask + lastPart;
        } else {
          maskedValue = firstPart + lastPart;
        }
      } else {
        // Mask the entire value
        maskedValue = preserveLength ? maskChar.repeat(value.length) : maskChar;
      }
      
      // Replace the value in the text
      maskedText = maskedText.substring(0, startIndex) + 
                   maskedValue + 
                   maskedText.substring(endIndex);
    }
    
    return maskedText;
  }

  /**
   * Check if a field is whitelisted
   * @param value Field value
   * @param whitelist Whitelist patterns
   * @returns True if whitelisted
   */
  private isFieldWhitelisted(value: string, whitelist: string[]): boolean {
    return whitelist.some(pattern => {
      if (pattern.includes('*')) {
        // Convert glob pattern to regex
        const regexPattern = pattern
          .replace(/\./g, '\\.')
          .replace(/\*/g, '.*');
        return new RegExp(`^${regexPattern}$`).test(value);
      }
      return value === pattern;
    });
  }

  /**
   * Check if a field is blacklisted
   * @param value Field value
   * @param blacklist Blacklist patterns
   * @returns True if blacklisted
   */
  private isFieldBlacklisted(value: string, blacklist: string[]): boolean {
    return blacklist.some(pattern => {
      if (pattern.includes('*')) {
        // Convert glob pattern to regex
        const regexPattern = pattern
          .replace(/\./g, '\\.')
          .replace(/\*/g, '.*');
        return new RegExp(`^${regexPattern}$`).test(value);
      }
      return value === pattern;
    });
  }
}