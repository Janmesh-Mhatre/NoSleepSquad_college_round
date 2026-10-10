import crypto from "node:crypto";
import {
  Identity,
  Group,
  generateProof,
  verifyProof,
  type SemaphoreProof,
} from "@semaphore-protocol/core";
import { getDatabase } from "../db.js";

export type ZkMembershipProof = SemaphoreProof;

export interface MerkleMembershipPath {
  root: string;
  leafIndex: number;
  siblings: string[];
  totalLeaves: number;
}

/**
 * Real Semaphore-style Zero-Knowledge Anonymous Group Membership Proof Service
 * Powered by @semaphore-protocol/core (Groth16 zk-SNARK over BN254 / Poseidon).
 */
export class ZkProofService {
  private semaphoreGroup: Group;

  constructor() {
    this.initDatabaseTable();
    this.semaphoreGroup = new Group();
    this.loadLeavesFromDb();
  }

  private initDatabaseTable() {
    const db = getDatabase();
    db.exec(`
      CREATE TABLE IF NOT EXISTS membership_commitments (
        leaf_index INTEGER PRIMARY KEY,
        commitment TEXT UNIQUE NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS membership_roots (
        root TEXT PRIMARY KEY,
        leaf_count INTEGER NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        created_at TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS used_nullifiers (
        nullifier TEXT PRIMARY KEY,
        topic_scope TEXT NOT NULL,
        report_id TEXT,
        created_at TEXT NOT NULL
      );
    `);
  }

  private loadLeavesFromDb() {
    const db = getDatabase();
    const rows = db.prepare(`
      SELECT leaf_index as leafIndex, commitment, is_active as isActive
      FROM membership_commitments 
      ORDER BY leaf_index ASC
    `).all() as { leafIndex: number; commitment: string; isActive: number }[];

    if (rows.length === 0) {
      // Initialize tree with a safe unprovable non-member anchor scalar (SHA-256 mod BN254 scalar field)
      // Contains no discrete logarithm or known Semaphore private key, preventing anyone from generating false proofs
      const unprovableAnchorScalar = (BigInt("0x" + crypto.createHash("sha256").update("INCOGNITO:UNPROVABLE:GENESIS:NON_MEMBER:V2").digest("hex")) >> 8n).toString();

      const now = new Date().toISOString();
      db.prepare(`
        INSERT OR IGNORE INTO membership_commitments (leaf_index, commitment, is_active, created_at)
        VALUES (0, ?, 1, ?)
      `).run(unprovableAnchorScalar, now);

      this.semaphoreGroup = new Group([BigInt(unprovableAnchorScalar)]);
      const activeRoot = this.semaphoreGroup.root.toString();

      db.prepare(`
        INSERT OR REPLACE INTO membership_roots (root, leaf_count, is_active, created_at)
        VALUES (?, 1, 1, ?)
      `).run(activeRoot, now);
    } else {
      const activeMembers: bigint[] = [];
      for (const r of rows) {
        if (r.isActive !== 1) continue;
        try {
          if (/^\d+$/.test(r.commitment)) {
            activeMembers.push(BigInt(r.commitment));
          } else if (/^[0-9a-fA-F]+$/.test(r.commitment)) {
            activeMembers.push(BigInt("0x" + r.commitment) >> 8n);
          } else if (r.commitment.startsWith("0x")) {
            activeMembers.push(BigInt(r.commitment) >> 8n);
          }
        } catch {
          // Skip invalid legacy format
        }
      }

      this.semaphoreGroup = new Group(activeMembers.length > 0 ? activeMembers : [0n]);
      const activeRoot = this.semaphoreGroup.root.toString();
      const now = new Date().toISOString();

      db.prepare(`
        INSERT OR REPLACE INTO membership_roots (root, leaf_count, is_active, created_at)
        VALUES (?, ?, 1, ?)
      `).run(activeRoot, activeMembers.length, now);
    }
  }

  /**
   * Computes canonical topic scope as a 248-bit BigInt (strictly within BN254 scalar field).
   * Guarantees cross-topic unlinkability and same-topic determinism.
   */
  computeCanonicalScope(topic: string): bigint {
    const hash = crypto
      .createHash("sha256")
      .update(`INCOGNITO-SCOPE-V2:${topic.trim()}`)
      .digest("hex");
    return BigInt("0x" + hash) >> 8n;
  }

  /**
   * Computes canonical signal binding scalar as a 248-bit BigInt.
   * Binds the report content to the proof without exposing private data.
   */
  computeCanonicalSignal(reportBody: string): bigint {
    const hash = crypto
      .createHash("sha256")
      .update(`INCOGNITO-SIGNAL-V2:${reportBody.trim()}`)
      .digest("hex");
    return BigInt("0x" + hash) >> 8n;
  }

  /**
   * Registers a new anonymous member's identity commitment in the institutional Semaphore group.
   * Note: The commitment is an opaque cryptographic public key point. It does NOT store student identity.
   */
  registerCommitment(commitment: string): { root: string; leafIndex: number } {
    if (!commitment || typeof commitment !== "string") {
      throw new Error("Valid commitment string is required.");
    }

    const commitmentBigInt = BigInt(commitment);
    const db = getDatabase();

    const existing = db
      .prepare("SELECT leaf_index as leafIndex, is_active as isActive FROM membership_commitments WHERE commitment = ?")
      .get(commitment) as { leafIndex: number; isActive: number } | undefined;

    if (existing) {
      if (existing.isActive === 1) {
        return {
          root: this.semaphoreGroup.root.toString(),
          leafIndex: existing.leafIndex,
        };
      }
      // Re-activate previously revoked
      db.prepare("UPDATE membership_commitments SET is_active = 1 WHERE commitment = ?").run(commitment);
      this.loadLeavesFromDb();
      return {
        root: this.semaphoreGroup.root.toString(),
        leafIndex: existing.leafIndex,
      };
    }

    const maxRow = db
      .prepare("SELECT COALESCE(MAX(leaf_index), -1) as maxIdx FROM membership_commitments")
      .get() as { maxIdx: number };
    const newIndex = maxRow.maxIdx + 1;

    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO membership_commitments (leaf_index, commitment, is_active, created_at)
      VALUES (?, ?, 1, ?)
    `).run(newIndex, commitment, now);

    this.semaphoreGroup.addMember(commitmentBigInt);
    const activeRoot = this.semaphoreGroup.root.toString();

    db.prepare(`
      INSERT OR REPLACE INTO membership_roots (root, leaf_count, is_active, created_at)
      VALUES (?, ?, 1, ?)
    `).run(activeRoot, this.semaphoreGroup.members.length, now);

    return {
      root: activeRoot,
      leafIndex: newIndex,
    };
  }

  /**
   * Revokes a member commitment by deactivating it in the group and rotating the active root.
   */
  revokeCommitment(commitment: string): void {
    const db = getDatabase();
    db.prepare("UPDATE membership_commitments SET is_active = 0 WHERE commitment = ?").run(commitment);

    // Deactivate previous roots in the registry
    db.prepare("UPDATE membership_roots SET is_active = 0").run();

    // Rebuild active group
    this.loadLeavesFromDb();
  }

  /**
   * Generates a REAL Groth16 zk-SNARK zero-knowledge membership proof using @semaphore-protocol/core.
   * Proves that the prover holds an identity enrolled in the active institutional group,
   * bound to the specified topic scope and report body signal, without revealing the identity.
   */
  async generateProof(params: {
    identity: Identity;
    group?: Group;
    topicScope: string;
    reportBody: string;
  }): Promise<SemaphoreProof> {
    const targetGroup = params.group || this.semaphoreGroup;
    const scopeScalar = this.computeCanonicalScope(params.topicScope);
    const signalScalar = this.computeCanonicalSignal(params.reportBody);

    // generateProof(identity, group, message, scope)
    const proof = await generateProof(
      params.identity,
      targetGroup,
      signalScalar,
      scopeScalar
    );

    return proof;
  }

  /**
   * Cryptographically verifies a Semaphore zero-knowledge membership proof.
   * The verifier learns that the prover belongs to the eligible group without learning:
   * - student ID, name, or email
   * - identity secret / private key
   * - which membership commitment belongs to the prover
   */
  async verifyProof(
    proof: SemaphoreProof,
    expectedTopic: string,
    reportBody: string
  ): Promise<{ valid: boolean; reason?: string }> {
    if (!proof || typeof proof !== "object") {
      return { valid: false, reason: "Proof object is required." };
    }

    // 1. Structure validation
    if (
      !proof.merkleTreeRoot ||
      !proof.nullifier ||
      !proof.message ||
      !proof.scope ||
      !Array.isArray(proof.points) ||
      proof.points.length !== 8
    ) {
      return { valid: false, reason: "Malformed Semaphore proof structure or missing Groth16 points." };
    }

    // 2. Topic Scope validation
    const expectedScope = this.computeCanonicalScope(expectedTopic).toString();
    if (proof.scope !== expectedScope) {
      return {
        valid: false,
        reason: `Proof topic scope '${proof.scope}' does not match expected category scope '${expectedScope}'.`,
      };
    }

    // 3. Signal binding validation
    const expectedSignal = this.computeCanonicalSignal(reportBody).toString();
    if (proof.message !== expectedSignal) {
      return {
        valid: false,
        reason: "Proof signal does not bind to submitted report body.",
      };
    }

    // 4. Institutional Group Root verification
    const db = getDatabase();
    const rootRow = db
      .prepare("SELECT root, is_active as isActive FROM membership_roots WHERE root = ?")
      .get(proof.merkleTreeRoot) as { root: string; isActive: number } | undefined;

    if (!rootRow || rootRow.isActive !== 1) {
      return {
        valid: false,
        reason: "Merkle root is not active in the institutional registry or has been revoked.",
      };
    }

    // 5. Replay / Duplicate nullifier check
    const usedNullifier = db
      .prepare("SELECT nullifier FROM used_nullifiers WHERE nullifier = ?")
      .get(proof.nullifier);

    if (usedNullifier) {
      return {
        valid: false,
        reason: "Nullifier has already been used for a submission in this reporting scope.",
      };
    }

    // 6. Cryptographic Groth16 zk-SNARK verification
    try {
      const isGroth16Valid = await verifyProof(proof);
      if (!isGroth16Valid) {
        return { valid: false, reason: "Cryptographic Groth16 zero-knowledge proof verification failed." };
      }
    } catch (err) {
      const errMsg = err instanceof Error ? err.message : String(err);
      return { valid: false, reason: `Proof verification error: ${errMsg}` };
    }

    return { valid: true };
  }

  /**
   * Atomically records and consumes a verified nullifier to prevent replay attacks under the same scope.
   * Uses an atomic database insert with unique constraint; throws if already consumed.
   */
  consumeNullifier(nullifier: string, topicScope: string, reportId?: string): void {
    const db = getDatabase();
    const now = new Date().toISOString();
    try {
      db.prepare(`
        INSERT INTO used_nullifiers (nullifier, topic_scope, report_id, created_at)
        VALUES (?, ?, ?, ?)
      `).run(nullifier, topicScope, reportId || null, now);
    } catch (err: any) {
      if (
        err?.code === "SQLITE_CONSTRAINT_PRIMARYKEY" ||
        err?.message?.includes("UNIQUE constraint failed") ||
        err?.code === "23505"
      ) {
        throw new Error("Nullifier replay detected: nullifier has already been consumed for this topic scope.");
      }
      throw err;
    }
  }

  recordNullifier(nullifier: string, topicScope: string, reportId?: string): void {
    try {
      this.consumeNullifier(nullifier, topicScope, reportId);
    } catch {
      // Compatibility fallback for non-throwing callers
    }
  }

  getActiveRoot(): string {
    return this.semaphoreGroup.root.toString();
  }

  getGroup(): Group {
    return this.semaphoreGroup;
  }
}

export const zkProofService = new ZkProofService();
