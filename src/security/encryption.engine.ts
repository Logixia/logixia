/**
 * Encryption Engine for Logixia
 * 
 * Provides encryption and decryption capabilities for sensitive log data
 * Supports field-level encryption, key management, and multiple algorithms
 */

import * as crypto from 'crypto';
import { 
  EncryptionAlgorithm, 
  EncryptedData, 
  EncryptionConfig 
} from '../types/security.types';

/**
 * Interface for key manager
 */
export interface IKeyManager {
  generateKey(keyId?: string, algorithm?: EncryptionAlgorithm): Promise<{ keyId: string, key: Buffer }>;
  getKey(keyId: string): Promise<Buffer>;
  rotateKey(oldKeyId: string, newKeyId?: string): Promise<string>;
  revokeKey(keyId: string): Promise<void>;
  listKeys(): Promise<KeyInfo[]>;
  getFieldKey(fieldName: string): Promise<{ keyId: string, key: Buffer }>;
}

/**
 * Key information
 */
export interface KeyInfo {
  id: string;
  algorithm: EncryptionAlgorithm;
  createdAt: Date;
  lastRotated?: Date;
  status: 'active' | 'rotating' | 'revoked';
}

/**
 * Interface for field-level encryption
 */
export interface IFieldEncryption {
  encryptField(fieldName: string, value: any): Promise<EncryptedData>;
  decryptField(fieldName: string, encryptedValue: EncryptedData): Promise<any>;
}

/**
 * Interface for encryption engine
 */
export interface IEncryptionEngine {
  encrypt(data: string, keyId?: string): Promise<EncryptedData>;
  decrypt(encryptedData: EncryptedData): Promise<string>;
  generateKey(algorithm?: EncryptionAlgorithm): Promise<{ keyId: string, key: Buffer }>;
  rotateKey(oldKeyId: string, newKeyId?: string): Promise<string>;
  isEnabled(): boolean;
  getKeyManager(): IKeyManager;
  getFieldEncryption(): IFieldEncryption;
}

/**
 * Default implementation of key manager
 */
export class KeyManager implements IKeyManager {
  private keys: Map<string, { key: Buffer, info: KeyInfo }> = new Map();
  private fieldKeys: Map<string, string> = new Map(); // Maps field names to key IDs
  private config: EncryptionConfig;
  private defaultKeyId: string;

  constructor(config: EncryptionConfig) {
    this.config = config || { enabled: false };
    
    // Initialize with existing key if provided
    if (this.config.enabled && this.config.keyId) {
      this.defaultKeyId = this.config.keyId;
      // In a real implementation, we would load the key from the provider
      // For now, we'll generate a deterministic key based on the keyId
      const key = crypto.createHash('sha256').update(this.config.keyId).digest();
      this.keys.set(this.config.keyId, {
        key,
        info: {
          id: this.config.keyId,
          algorithm: this.config.algorithm || EncryptionAlgorithm.AES_256_GCM,
          createdAt: new Date(),
          status: 'active'
        }
      });
    }
  }

  /**
   * Generate a new encryption key
   * @param keyId Optional key ID
   * @param algorithm Optional algorithm to use for key generation
   * @returns Object containing key ID and key
   */
  async generateKey(keyId?: string, algorithm?: EncryptionAlgorithm): Promise<{ keyId: string, key: Buffer }> {
    const alg = algorithm || this.config.algorithm || EncryptionAlgorithm.AES_256_GCM;
    
    let keySize: number;
    switch (alg) {
      case EncryptionAlgorithm.AES_256_GCM:
      case EncryptionAlgorithm.CHACHA20_POLY1305:
        keySize = 32; // 256 bits
        break;
      case EncryptionAlgorithm.RSA_OAEP:
        // For RSA, we would generate a key pair
        // This is a simplified implementation
        keySize = 32; // Placeholder
        break;
      default:
        keySize = 32;
    }
    
    // Generate a random key
    const key = crypto.randomBytes(keySize);
    
    // Generate a unique key ID if not provided
    const actualKeyId = keyId || crypto.randomUUID();
    
    // Store the key with its metadata
    this.keys.set(actualKeyId, {
      key,
      info: {
        id: actualKeyId,
        algorithm: alg,
        createdAt: new Date(),
        status: 'active'
      }
    });
    
    // Update the default key ID if this is the first key
    if (!this.defaultKeyId) {
      this.defaultKeyId = actualKeyId;
    }
    
    return { keyId: actualKeyId, key };
  }

  /**
   * Get a key by ID
   * @param keyId Key ID
   * @returns Key buffer
   */
  async getKey(keyId: string): Promise<Buffer> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key not found: ${keyId}`);
    }
    
    if (keyEntry.info.status === 'revoked') {
      throw new Error(`Key has been revoked: ${keyId}`);
    }
    
    return keyEntry.key;
  }

  /**
   * Rotate an encryption key
   * @param oldKeyId ID of the key to rotate
   * @param newKeyId Optional ID for the new key
   * @returns ID of the new key
   */
  async rotateKey(oldKeyId: string, newKeyId?: string): Promise<string> {
    const oldKeyEntry = this.keys.get(oldKeyId);
    if (!oldKeyEntry) {
      throw new Error(`Key not found: ${oldKeyId}`);
    }
    
    // Generate a new key with the same algorithm
    const { keyId, key } = await this.generateKey(newKeyId, oldKeyEntry.info.algorithm);
    
    // Update the old key's status
    oldKeyEntry.info.status = 'rotating';
    oldKeyEntry.info.lastRotated = new Date();
    
    // Update field mappings to use the new key
    for (const [field, mappedKeyId] of this.fieldKeys.entries()) {
      if (mappedKeyId === oldKeyId) {
        this.fieldKeys.set(field, keyId);
      }
    }
    
    // Update the default key ID if the rotated key was the default
    if (oldKeyId === this.defaultKeyId) {
      this.defaultKeyId = keyId;
    }
    
    return keyId;
  }

  /**
   * Revoke a key
   * @param keyId ID of the key to revoke
   */
  async revokeKey(keyId: string): Promise<void> {
    const keyEntry = this.keys.get(keyId);
    if (!keyEntry) {
      throw new Error(`Key not found: ${keyId}`);
    }
    
    // Update the key's status
    keyEntry.info.status = 'revoked';
    
    // Remove field mappings for this key
    for (const [field, mappedKeyId] of this.fieldKeys.entries()) {
      if (mappedKeyId === keyId) {
        this.fieldKeys.delete(field);
      }
    }
    
    // If this was the default key, we need a new default
    if (keyId === this.defaultKeyId) {
      // Find the first active key
      for (const [id, entry] of this.keys.entries()) {
        if (entry.info.status === 'active') {
          this.defaultKeyId = id;
          break;
        }
      }
    }
  }

  /**
   * List all keys
   * @returns Array of key information
   */
  async listKeys(): Promise<KeyInfo[]> {
    return Array.from(this.keys.values()).map(entry => entry.info);
  }

  /**
   * Get or create a key for a specific field
   * @param fieldName Field name
   * @returns Key ID and key buffer
   */
  async getFieldKey(fieldName: string): Promise<{ keyId: string, key: Buffer }> {
    // Check if field already has a key assigned
    const existingKeyId = this.fieldKeys.get(fieldName);
    if (existingKeyId) {
      try {
        const key = await this.getKey(existingKeyId);
        return { keyId: existingKeyId, key };
      } catch (error) {
        // Key might be revoked or deleted, fall through to create a new one
        console.warn(`Failed to get field key for ${fieldName}, creating new key:`, error);
      }
    }
    
    // Use default key if available
    if (this.defaultKeyId) {
      try {
        const key = await this.getKey(this.defaultKeyId);
        this.fieldKeys.set(fieldName, this.defaultKeyId);
        return { keyId: this.defaultKeyId, key };
      } catch (error) {
        // Default key might be revoked or deleted, fall through to create a new one
        console.warn('Failed to use default key, creating new key:', error);
      }
    }
    
    // Create a new key for this field
    const { keyId, key } = await this.generateKey();
    this.fieldKeys.set(fieldName, keyId);
    return { keyId, key };
  }
}

/**
 * Field-level encryption implementation
 */
export class FieldEncryption implements IFieldEncryption {
  private keyManager: IKeyManager;
  private encryptionEngine: IEncryptionEngine;

  constructor(keyManager: IKeyManager, encryptionEngine: IEncryptionEngine) {
    this.keyManager = keyManager;
    this.encryptionEngine = encryptionEngine;
  }

  /**
   * Encrypt a field
   * @param fieldName Field name
   * @param value Field value
   * @returns Encrypted data
   */
  async encryptField(fieldName: string, value: any): Promise<EncryptedData> {
    const { keyId } = await this.keyManager.getFieldKey(fieldName);
    return await this.encryptionEngine.encrypt(JSON.stringify(value), keyId);
  }

  /**
   * Decrypt a field
   * @param fieldName Field name
   * @param encryptedValue Encrypted value
   * @returns Decrypted value
   */
  async decryptField(fieldName: string, encryptedValue: EncryptedData): Promise<any> {
    const decrypted = await this.encryptionEngine.decrypt(encryptedValue);
    return JSON.parse(decrypted);
  }
}

/**
 * Default implementation of encryption engine using Node.js crypto
 */
export class EncryptionEngine implements IEncryptionEngine {
  private config: EncryptionConfig;
  private keyManager: KeyManager;
  private fieldEncryption: FieldEncryption;

  constructor(config: EncryptionConfig) {
    this.config = config || { enabled: false };
    
    // Initialize key manager
    this.keyManager = new KeyManager(this.config);
    
    // Generate a default key if none exists
    if (this.config.enabled && !this.config.keyId) {
      this.keyManager.generateKey().catch(err => {
        console.error('Failed to generate default encryption key:', err);
        this.config.enabled = false;
      });
    }
    
    // Initialize field encryption
    this.fieldEncryption = new FieldEncryption(this.keyManager, this);
  }

  /**
   * Check if encryption is enabled
   */
  isEnabled(): boolean {
    return this.config.enabled === true;
  }

  /**
   * Get the key manager
   */
  getKeyManager(): IKeyManager {
    return this.keyManager;
  }

  /**
   * Get the field encryption
   */
  getFieldEncryption(): IFieldEncryption {
    return this.fieldEncryption;
  }

  /**
   * Encrypt data using the specified algorithm
   * @param data Data to encrypt
   * @param keyId Optional key ID to use for encryption
   * @returns Encrypted data object
   */
  async encrypt(data: string, keyId?: string): Promise<EncryptedData> {
    if (!this.isEnabled()) {
      throw new Error('Encryption is not enabled');
    }

    const algorithm = this.config.algorithm || EncryptionAlgorithm.AES_256_GCM;
    let key: Buffer;
    let actualKeyId: string;

    if (keyId) {
      // Use the specified key
      key = await this.keyManager.getKey(keyId);
      actualKeyId = keyId;
    } else {
      // Get the default key
      const keyInfo = await this.keyManager.getFieldKey('default');
      key = keyInfo.key;
      actualKeyId = keyInfo.keyId;
    }

    try {
      // Generate a random initialization vector
      const iv = crypto.randomBytes(16);
      
      let cipher: crypto.CipherGCM | crypto.Cipher;
      let tag: Buffer | undefined;
      
      if (algorithm === EncryptionAlgorithm.AES_256_GCM) {
        cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const encrypted = Buffer.concat([
          cipher.update(Buffer.from(data, 'utf8')),
          cipher.final()
        ]);
        tag = cipher.getAuthTag();
        
        return {
          algorithm,
          iv: iv.toString('base64'),
          data: encrypted.toString('base64'),
          keyId: actualKeyId,
          tag: tag.toString('base64')
        };
      } else if (algorithm === EncryptionAlgorithm.CHACHA20_POLY1305) {
        // Note: Node.js doesn't natively support ChaCha20-Poly1305
        // This is a placeholder for when it's available or using a library
        throw new Error('ChaCha20-Poly1305 is not yet supported');
      } else if (algorithm === EncryptionAlgorithm.RSA_OAEP) {
        // For RSA, we would use publicEncrypt instead
        // This is a simplified implementation
        const encrypted = crypto.publicEncrypt(
          {
            key: key.toString('utf8'),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
          },
          Buffer.from(data, 'utf8')
        );
        
        return {
          algorithm,
          iv: '', // RSA doesn't use IV
          data: encrypted.toString('base64'),
          keyId: actualKeyId
        };
      } else {
        // Default to AES-256-CBC for other algorithms
        cipher = crypto.createCipheriv('aes-256-cbc', key, iv);
        const encrypted = Buffer.concat([
          cipher.update(Buffer.from(data, 'utf8')),
          cipher.final()
        ]);
        
        return {
          algorithm,
          iv: iv.toString('base64'),
          data: encrypted.toString('base64'),
          keyId: actualKeyId
        };
      }
    } catch (error) {
      console.error('Encryption failed:', error);
      throw new Error(`Encryption failed: ${error.message}`);
    }
  }

  /**
   * Decrypt data using the specified algorithm
   * @param encryptedData Encrypted data object
   * @returns Decrypted data as string
   */
  async decrypt(encryptedData: EncryptedData): Promise<string> {
    if (!this.isEnabled()) {
      throw new Error('Encryption is not enabled');
    }

    const { algorithm, iv, data, keyId, tag } = encryptedData;
    
    if (!keyId) {
      throw new Error('Key ID is missing from encrypted data');
    }
    
    // Get the key from the key manager
    const key = await this.keyManager.getKey(keyId);

    try {
      if (algorithm === EncryptionAlgorithm.AES_256_GCM) {
        if (!tag) {
          throw new Error('Authentication tag is missing for AES-GCM decryption');
        }
        
        const decipher = crypto.createDecipheriv(
          'aes-256-gcm',
          key,
          Buffer.from(iv, 'base64')
        );
        
        decipher.setAuthTag(Buffer.from(tag, 'base64'));
        
        const decrypted = Buffer.concat([
          decipher.update(Buffer.from(data, 'base64')),
          decipher.final()
        ]);
        
        return decrypted.toString('utf8');
      } else if (algorithm === EncryptionAlgorithm.CHACHA20_POLY1305) {
        // Note: Node.js doesn't natively support ChaCha20-Poly1305
        throw new Error('ChaCha20-Poly1305 is not yet supported');
      } else if (algorithm === EncryptionAlgorithm.RSA_OAEP) {
        // For RSA, we would use privateDecrypt
        const decrypted = crypto.privateDecrypt(
          {
            key: key.toString('utf8'),
            padding: crypto.constants.RSA_PKCS1_OAEP_PADDING
          },
          Buffer.from(data, 'base64')
        );
        
        return decrypted.toString('utf8');
      } else {
        // Default to AES-256-CBC for other algorithms
        const decipher = crypto.createDecipheriv(
          'aes-256-cbc',
          key,
          Buffer.from(iv, 'base64')
        );
        
        const decrypted = Buffer.concat([
          decipher.update(Buffer.from(data, 'base64')),
          decipher.final()
        ]);
        
        return decrypted.toString('utf8');
      }
    } catch (error) {
      console.error('Decryption failed:', error);
      throw new Error(`Decryption failed: ${error.message}`);
    }
  }

  /**
   * Generate a new encryption key
   * @param algorithm Optional algorithm to use for key generation
   * @returns Object containing key ID and key
   */
  async generateKey(algorithm?: EncryptionAlgorithm): Promise<{ keyId: string, key: Buffer }> {
    return await this.keyManager.generateKey(undefined, algorithm);
  }

  /**
   * Rotate an encryption key
   * @param oldKeyId ID of the key to rotate
   * @param newKeyId Optional ID for the new key
   * @returns ID of the new key
   */
  async rotateKey(oldKeyId: string, newKeyId?: string): Promise<string> {
    if (!this.isEnabled()) {
      throw new Error('Encryption is not enabled');
    }
    
    return await this.keyManager.rotateKey(oldKeyId, newKeyId);
  }
}