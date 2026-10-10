import crypto from "node:crypto";
import { env } from "../config/env.js";

export interface KeyProvider {
  getKey(): Buffer;
  providerType: "development" | "production_kms";
}

export class DevelopmentKeyProvider implements KeyProvider {
  public readonly providerType = "development" as const;
  private key: Buffer;

  constructor(seedKey?: string) {
    if (seedKey && seedKey.length >= 16) {
      this.key = crypto.createHash("sha256").update(seedKey).digest();
    } else {
      this.key = crypto.randomBytes(32);
    }
  }

  getKey(): Buffer {
    return this.key;
  }
}

export class ProductionKMSProvider implements KeyProvider {
  public readonly providerType = "production_kms" as const;
  private key: Buffer;

  constructor(kmsKeyArnOrSecret?: string) {
    const rawKey = kmsKeyArnOrSecret || process.env.ENCRYPTION_KEY || env.encryptionKey;
    if (!rawKey || rawKey.length < 32 || rawKey.includes("dev-only") || rawKey.includes("default")) {
      throw new Error(
        "FATAL: Production environment requires a securely injected ENCRYPTION_KEY of at least 32 bytes from KMS/vault."
      );
    }
    this.key = crypto.createHash("sha256").update(rawKey).digest();
  }

  getKey(): Buffer {
    return this.key;
  }
}

/**
 * Key Management Service for Incognito
 * Handles cryptographic key lifecycle, validation, and domain derivation.
 */
export class KeyManagementService {
  private provider: KeyProvider;

  constructor(customProvider?: KeyProvider) {
    if (customProvider) {
      this.provider = customProvider;
    } else {
      const isProd = process.env.NODE_ENV === "production" || env.nodeEnv === "production";
      if (isProd) {
        this.provider = new ProductionKMSProvider();
      } else {
        const rawKey = process.env.ENCRYPTION_KEY || env.encryptionKey;
        this.provider = new DevelopmentKeyProvider(rawKey);
      }
    }
  }

  getMasterKey(): Buffer {
    return this.provider.getKey();
  }

  getProvider(): KeyProvider {
    return this.provider;
  }

  /**
   * Derives a domain-specific subkey using HKDF-like HMAC-SHA256 derivation
   */
  deriveSubkey(context: string): Buffer {
    return crypto
      .createHmac("sha256", this.provider.getKey())
      .update(`INCOGNITO-KDF-V2:${context}`)
      .digest();
  }
}

export const keyService = new KeyManagementService();
