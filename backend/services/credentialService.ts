import crypto from "node:crypto";
import { getDatabase } from "../db.js";
import type { CredentialRecord } from "../models/membership.js";
import { zkProofService } from "./zkProofService.js";

export const SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617n;

/**
 * Validates whether a value is a valid Semaphore identity commitment
 * (a non-zero scalar strictly within the BN254 snark scalar field).
 */
export function isValidSemaphoreCommitment(commitment: any): boolean {
  if (typeof commitment !== "string" && typeof commitment !== "number" && typeof commitment !== "bigint") {
    return false;
  }
  const str = String(commitment).trim();
  if (!str || !/^[0-9]+$/.test(str)) {
    return false;
  }
  try {
    const val = BigInt(str);
    return val > 0n && val < SNARK_SCALAR_FIELD;
  } catch {
    return false;
  }
}

export interface CredentialEnrollmentResult extends CredentialRecord {
  root?: string;
  leafIndex?: number;
}

export interface CredentialProvider {
  createCredential(memberId: string, memberRef: string, clientCommitment?: string): CredentialEnrollmentResult;
  getCredentialByMemberId(memberId: string): CredentialRecord | null;
  revokeCredential(memberId: string): void;
  validateCredential(memberId: string): boolean;
}

export class LocalCredentialProvider implements CredentialProvider {
  /**
   * Issues an anonymous Semaphore credential using a client-provided public commitment.
   *
   * Security Invariants:
   * 1. The client generates and retains its own Semaphore identity secret.
   * 2. The server NEVER generates, exports, receives, persists, or transmits identity secrets.
   * 3. Commitments are strictly validated as valid BN254 scalar field elements.
   */
  createCredential(memberId: string, _memberRef: string, clientCommitment?: string): CredentialEnrollmentResult {
    if (!clientCommitment || !isValidSemaphoreCommitment(clientCommitment)) {
      throw new Error("A valid client-owned Semaphore identity commitment is required.");
    }

    const commitment = String(clientCommitment).trim();
    const db = getDatabase();
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();

    // Register into the anonymous Semaphore membership tree
    const regResult = zkProofService.registerCommitment(commitment);

    const stmt = db.prepare(`
      INSERT INTO credentials (id, member_id, commitment, status, created_at, updated_at, expires_at)
      VALUES (?, ?, ?, 'registered', ?, ?, ?)
    `);

    stmt.run(id, memberId, commitment, now, now, expiresAt);

    return {
      id,
      memberId,
      commitment,
      status: "registered",
      createdAt: now,
      updatedAt: now,
      expiresAt,
      root: regResult.root,
      leafIndex: regResult.leafIndex,
    };
  }

  getCredentialByMemberId(memberId: string): CredentialRecord | null {
    const db = getDatabase();
    const row = db.prepare(`
      SELECT id, member_id as memberId, commitment, status, created_at as createdAt, updated_at as updatedAt, expires_at as expiresAt
      FROM credentials
      WHERE member_id = ?
    `).get(memberId) as CredentialRecord | undefined;

    return row || null;
  }

  revokeCredential(memberId: string): void {
    const db = getDatabase();
    const now = new Date().toISOString();
    const cred = this.getCredentialByMemberId(memberId);
    if (cred) {
      zkProofService.revokeCommitment(cred.commitment);
    }
    db.prepare(`
      UPDATE credentials
      SET status = 'revoked', updated_at = ?
      WHERE member_id = ?
    `).run(now, memberId);
  }

  validateCredential(memberId: string): boolean {
    const cred = this.getCredentialByMemberId(memberId);
    if (!cred || cred.status !== "registered") return false;
    if (cred.expiresAt && new Date(cred.expiresAt) < new Date()) {
      return false;
    }
    return true;
  }
}

export const credentialProvider: CredentialProvider = new LocalCredentialProvider();
