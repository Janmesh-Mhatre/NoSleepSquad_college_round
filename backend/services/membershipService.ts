import crypto from "node:crypto";
import { getDatabase } from "../db.js";
import type {
  MemberRecord,
  MembershipStatusDTO,
  EnrollMemberResponse,
  RevokeMemberResponse,
  ValidateMemberResponse,
} from "../models/membership.js";
import { credentialProvider, isValidSemaphoreCommitment } from "./credentialService.js";

export class MembershipError extends Error {
  constructor(public code: string, message: string, public status: number = 400) {
    super(message);
    this.name = "MembershipError";
  }
}

export interface MembershipService {
  getStatus(memberRef: string): MembershipStatusDTO;
  enroll(memberRef: string, clientCommitment?: string): EnrollMemberResponse;
  revoke(memberRef: string, reason?: string): RevokeMemberResponse;
  validate(memberRef: string): ValidateMemberResponse;
  getMemberByRef(memberRef: string): MemberRecord | null;
}

export class SqliteMembershipService implements MembershipService {
  getMemberByRef(memberRef: string): MemberRecord | null {
    if (!memberRef || typeof memberRef !== "string" || !memberRef.trim()) {
      return null;
    }
    const db = getDatabase();
    const row = db.prepare(`
      SELECT 
        id, 
        member_ref as memberRef, 
        status, 
        created_at as createdAt, 
        updated_at as updatedAt, 
        revoked_at as revokedAt, 
        revocation_reason as revocationReason
      FROM members
      WHERE member_ref = ?
    `).get(memberRef.trim()) as MemberRecord | undefined;

    return row || null;
  }

  getStatus(memberRef: string): MembershipStatusDTO {
    const member = this.getMemberByRef(memberRef);
    if (!member) {
      return {
        registered: false,
        active: false,
        status: "not_registered",
        credentialRegistered: false,
        credentialStatus: "none",
        anonymousVerificationReady: false,
      };
    }

    const cred = credentialProvider.getCredentialByMemberId(member.id);
    const isCredRegistered = cred?.status === "registered";

    return {
      registered: true,
      active: member.status === "active",
      status: member.status,
      credentialRegistered: isCredRegistered,
      credentialStatus: cred ? cred.status : "none",
      anonymousVerificationReady: false,
      expiresAt: cred?.expiresAt,
    };
  }

  enroll(memberRef: string, clientCommitment?: string): EnrollMemberResponse {
    const sanitizedRef = memberRef?.trim();
    if (!sanitizedRef) {
      throw new MembershipError("invalid_request", "Member reference is required", 400);
    }

    if (!clientCommitment || !isValidSemaphoreCommitment(clientCommitment)) {
      throw new MembershipError(
        "invalid_commitment",
        "A valid client-owned Semaphore identity commitment is required for enrollment.",
        400
      );
    }

    const existing = this.getMemberByRef(sanitizedRef);
    if (existing) {
      throw new MembershipError("duplicate_enrollment", "Member is already enrolled", 409);
    }

    const db = getDatabase();
    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    const insertMember = db.prepare(`
      INSERT INTO members (id, member_ref, status, created_at, updated_at)
      VALUES (?, ?, 'active', ?, ?)
    `);

    insertMember.run(id, sanitizedRef, now, now);

    // Create associated credential commitment in anonymous Semaphore group
    const cred = credentialProvider.createCredential(id, sanitizedRef, clientCommitment);

    return {
      success: true,
      membership: {
        status: "active",
        createdAt: now,
      },
      credential: {
        status: cred.status,
        commitmentReference: cred.commitment.substring(0, 16) + "...",
        createdAt: cred.createdAt,
        expiresAt: cred.expiresAt || "",
        commitment: cred.commitment,
        root: cred.root,
      },
    };
  }

  revoke(memberRef: string, reason?: string): RevokeMemberResponse {
    const sanitizedRef = memberRef?.trim();
    if (!sanitizedRef) {
      throw new MembershipError("invalid_request", "Member reference is required", 400);
    }

    const member = this.getMemberByRef(sanitizedRef);
    if (!member) {
      throw new MembershipError("not_found", "Member not found", 404);
    }

    if (member.status === "revoked") {
      return {
        success: true,
        status: "revoked",
        revokedAt: member.revokedAt || new Date().toISOString(),
      };
    }

    const db = getDatabase();
    const now = new Date().toISOString();

    db.prepare(`
      UPDATE members
      SET status = 'revoked', updated_at = ?, revoked_at = ?, revocation_reason = ?
      WHERE id = ?
    `).run(now, now, reason || "Administrative revocation", member.id);

    // Revoke corresponding credential
    credentialProvider.revokeCredential(member.id);

    return {
      success: true,
      status: "revoked",
      revokedAt: now,
    };
  }

  validate(memberRef: string): ValidateMemberResponse {
    const sanitizedRef = memberRef?.trim();
    if (!sanitizedRef) {
      return {
        valid: false,
        status: "not_registered",
        active: false,
        credentialValid: false,
      };
    }

    const member = this.getMemberByRef(sanitizedRef);
    if (!member) {
      return {
        valid: false,
        status: "not_registered",
        active: false,
        credentialValid: false,
      };
    }

    const credValid = credentialProvider.validateCredential(member.id);
    const isActive = member.status === "active";
    const isValid = isActive && credValid;

    return {
      valid: isValid,
      status: member.status,
      active: isActive,
      credentialValid: credValid,
    };
  }
}

export const membershipService: MembershipService = new SqliteMembershipService();
