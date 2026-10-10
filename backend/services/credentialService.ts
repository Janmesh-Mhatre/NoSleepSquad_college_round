import crypto from "node:crypto";
import { Identity } from "@semaphore-protocol/core";
import { getDatabase } from "../db.js";
import type { CredentialRecord } from "../models/membership.js";
import { zkProofService } from "./zkProofService.js";

export interface CredentialEnrollmentResult extends CredentialRecord {
  root?: string;
  leafIndex?: number;
  identitySecretExport?: string;
}

export interface CredentialProvider {
  createCredential(memberId: string, memberRef: string, clientCommitment?: string): CredentialEnrollmentResult;
  getCredentialByMemberId(memberId: string): CredentialRecord | null;
  revokeCredential(memberId: string): void;
  validateCredential(memberId: string): boolean;
}

export class LocalCredentialProvider implements CredentialProvider {
  /**
   * Issues an anonymous Semaphore credential.
   * If the client provides a commitment, that commitment is registered in the group.
   * If none is provided, a fresh Semaphore Identity is generated; its commitment is registered,
   * and its exported secret is returned once to the client (not retained on the server).
   */
  createCredential(memberId: string, _memberRef: string, clientCommitment?: string): CredentialEnrollmentResult {
    const db = getDatabase();
    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const expiresAt = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();

    let commitment: string;
    let identitySecretExport: string | undefined;

    if (clientCommitment && typeof clientCommitment === "string") {
      commitment = clientCommitment.trim();
    } else {
      // Generate genuine Semaphore Identity with cryptographically secure randomness
      const newIdentity = new Identity();
      commitment = newIdentity.commitment.toString();
      identitySecretExport = newIdentity.export();
    }

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
      identitySecretExport,
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
