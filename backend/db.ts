import { DatabaseSync } from "node:sqlite";
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";
import pg from "pg";
import { env } from "./config/env.js";
import { MerkleTree } from "./services/merkleTree.js";

let dbInstance: DatabaseSync | null = null;
let pgPoolInstance: pg.Pool | null = null;

export function getPostgresPool(): pg.Pool | null {
  const connectionString = process.env.DATABASE_URL;
  if (!connectionString) return null;

  if (!pgPoolInstance) {
    pgPoolInstance = new pg.Pool({
      connectionString,
      max: 20,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: 3000,
    });
  }
  return pgPoolInstance;
}

export function getDatabase(): DatabaseSync {
  if (env.nodeEnv === "production" || process.env.NODE_ENV === "production") {
    const pgUrl = process.env.DATABASE_URL;
    if (!pgUrl || (!pgUrl.startsWith("postgres://") && !pgUrl.startsWith("postgresql://"))) {
      throw new Error(
        "FATAL: Production environment requires a valid PostgreSQL connection (DATABASE_URL starting with postgres:// or postgresql://). SQLite is strictly prohibited in production."
      );
    }
  }

  if (dbInstance) return dbInstance;

  const dbPath = env.databasePath;
  if (dbPath !== ":memory:") {
    const dir = path.dirname(dbPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  }

  const db = new DatabaseSync(dbPath);
  db.exec("PRAGMA foreign_keys = ON;");
  db.exec("PRAGMA busy_timeout = 5000;");
  if (dbPath !== ":memory:") {
    try {
      db.exec("PRAGMA journal_mode = WAL;");
    } catch {
      // WAL may not be supported on all environments
    }
  }

  initSchema(db);
  seedInitialData(db);

  dbInstance = db;
  return db;
}

function initSchema(db: DatabaseSync) {
  db.exec(`
    CREATE TABLE IF NOT EXISTS members (
      id TEXT PRIMARY KEY,
      member_ref TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'active', 'revoked')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      revoked_at TEXT,
      revocation_reason TEXT
    );

    CREATE TABLE IF NOT EXISTS credentials (
      id TEXT PRIMARY KEY,
      member_id TEXT NOT NULL,
      commitment TEXT UNIQUE NOT NULL,
      status TEXT NOT NULL CHECK(status IN ('pending', 'registered', 'revoked', 'expired')),
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      expires_at TEXT,
      FOREIGN KEY(member_id) REFERENCES members(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS categories (
      id TEXT PRIMARY KEY,
      name TEXT UNIQUE NOT NULL,
      description TEXT NOT NULL,
      risk_tier TEXT NOT NULL CHECK(risk_tier IN ('standard', 'elevated', 'urgent'))
    );

    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY,
      reference TEXT UNIQUE NOT NULL,
      status_secret_hash TEXT NOT NULL,
      category_id TEXT NOT NULL,
      encrypted_body TEXT NOT NULL,
      priority TEXT NOT NULL CHECK(priority IN ('low', 'medium', 'high', 'critical')),
      status TEXT NOT NULL CHECK(status IN ('received', 'under_review', 'moderation_review', 'assigned', 'action_taken', 'closed')),
      moderation_result TEXT NOT NULL,
      nullifier_hash TEXT UNIQUE NOT NULL,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL,
      assigned_moderator TEXT,
      audit_committed INTEGER DEFAULT 0,
      audit_batch_id TEXT,
      retention_expires_at TEXT,
      is_purged INTEGER DEFAULT 0,
      FOREIGN KEY(category_id) REFERENCES categories(id)
    );

    CREATE TABLE IF NOT EXISTS security_events (
      id TEXT PRIMARY KEY,
      event_type TEXT NOT NULL,
      severity TEXT NOT NULL CHECK(severity IN ('INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
      details TEXT NOT NULL,
      created_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS moderation_actions (
      id TEXT PRIMARY KEY,
      report_id TEXT NOT NULL,
      action TEXT NOT NULL,
      previous_status TEXT NOT NULL,
      new_status TEXT NOT NULL,
      reason TEXT NOT NULL,
      moderator_id TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(report_id) REFERENCES reports(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS audit_batches (
      id TEXT PRIMARY KEY,
      sequence INTEGER UNIQUE NOT NULL,
      merkle_root TEXT NOT NULL,
      report_count INTEGER NOT NULL,
      status TEXT NOT NULL,
      contract_address TEXT NOT NULL,
      network TEXT NOT NULL,
      tx_hash TEXT,
      block_number INTEGER,
      created_at TEXT NOT NULL,
      published_at TEXT
    );

    CREATE TABLE IF NOT EXISTS audit_records (
      id TEXT PRIMARY KEY,
      batch_id TEXT NOT NULL,
      report_reference TEXT NOT NULL,
      commitment_hash TEXT NOT NULL,
      created_at TEXT NOT NULL,
      FOREIGN KEY(batch_id) REFERENCES audit_batches(id) ON DELETE CASCADE
    );
  `);

  try {
    db.exec("ALTER TABLE reports ADD COLUMN retention_expires_at TEXT;");
  } catch {}
  try {
    db.exec("ALTER TABLE reports ADD COLUMN is_purged INTEGER DEFAULT 0;");
  } catch {}

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_members_ref ON members(member_ref);
    CREATE INDEX IF NOT EXISTS idx_credentials_member_id ON credentials(member_id);
    CREATE INDEX IF NOT EXISTS idx_reports_ref ON reports(reference);
    CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
    CREATE INDEX IF NOT EXISTS idx_reports_nullifier ON reports(nullifier_hash);
    CREATE INDEX IF NOT EXISTS idx_audit_batches_seq ON audit_batches(sequence);
    CREATE INDEX IF NOT EXISTS idx_reports_retention ON reports(retention_expires_at);
    CREATE INDEX IF NOT EXISTS idx_security_events_type ON security_events(event_type);
  `);
}

function seedInitialData(db: DatabaseSync) {
  // 1. Seed Categories if empty
  const catCount = db.prepare("SELECT count(*) as c FROM categories").get() as { c: number };
  if (catCount.c === 0) {
    const insertCat = db.prepare("INSERT INTO categories (id, name, description, risk_tier) VALUES (?, ?, ?, ?)");
    insertCat.run("cat-harassment", "Harassment", "Interpersonal harassment, discrimination, or abusive conduct", "urgent");
    insertCat.run("cat-misconduct", "Misconduct", "Policy breaches, conflict of interest, or ethical violations", "elevated");
    insertCat.run("cat-academic", "Academic concern", "Grading irregularity, credential dispute, or syllabus violations", "standard");
    insertCat.run("cat-institutional", "Institutional issue", "Administrative failure, resource allocation, or process abuse", "standard");
    insertCat.run("cat-safety", "Safety concern", "Facility hazard, physical safety violation, or laboratory hazard", "urgent");
    insertCat.run("cat-other", "Other", "General institutional concern not covered by standard categories", "standard");
  }

  // 2. Seed Demo Member only in local development when explicitly configured
  const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
  const isDev = (process.env.NODE_ENV || "development").toLowerCase() === "development" || (process.env.NODE_ENV || "development").toLowerCase() === "test";
  const devAuthAllowed = isDev && (process.env.ALLOW_DEV_AUTH === "true" || process.env.DEV_AUTH_ENABLED === "true");

  if (!isDeployed && devAuthAllowed) {
    const memberCount = db.prepare("SELECT count(*) as c FROM members").get() as { c: number };
    if (memberCount.c === 0) {
      const now = new Date().toISOString();
      const expires = new Date(Date.now() + 90 * 24 * 60 * 60 * 1000).toISOString();
      const memberId = "mem-demo-01";
      const credId = "cred-demo-01";
      const commitment = crypto.createHash("sha256").update("incognito:cred:demo-member-01:salt99").digest("hex");

      db.prepare("INSERT INTO members (id, member_ref, status, created_at, updated_at) VALUES (?, ?, 'active', ?, ?)")
        .run(memberId, "demo-member-01", now, now);

      db.prepare("INSERT INTO credentials (id, member_id, commitment, status, created_at, updated_at, expires_at) VALUES (?, ?, ?, 'registered', ?, ?, ?)")
        .run(credId, memberId, commitment, now, now, expires);
    }
  }

  // 3. Seed Sample Reports only in local development / testing
  if (!isDeployed && isDev) {
    const repCount = db.prepare("SELECT count(*) as c FROM reports").get() as { c: number };
    if (repCount.c === 0) {
    const now = new Date(Date.now() - 3600 * 1000 * 48).toISOString();
    const batchId = "batch-101";

    // Create 3 sample realistic institutional reports (anonymized, no PII)
    const reports = [
      {
        id: "rep-001",
        ref: "INC-849204",
        secret: "sec_a7f92e4b",
        cat: "cat-safety",
        body: "[Encrypted] Hazardous chemical ventilation failure reported in Chemistry Lab 3B during late-night research sessions.",
        priority: "high",
        status: "under_review",
        moderation: JSON.stringify({
          classification: "flagged",
          confidence: 0.94,
          policyVersion: "2026.4-standard",
          detectedSignals: ["Facility Safety", "Chemical Hazard", "Ventilation Failure"],
          urgencyScore: 82,
          reviewStatus: "automated"
        }),
        nullifier: crypto.createHash("sha256").update("nullifier:scope-safety:001").digest("hex"),
        mod: "mod-sec-01"
      },
      {
        id: "rep-002",
        ref: "INC-921058",
        secret: "sec_b3e18c99",
        cat: "cat-academic",
        body: "[Encrypted] Course assessment policy altered retroactively after final submissions without departmental approval.",
        priority: "medium",
        status: "received",
        moderation: JSON.stringify({
          classification: "cleared",
          confidence: 0.88,
          policyVersion: "2026.4-standard",
          detectedSignals: ["Academic Regulations", "Assessment Irregularity"],
          urgencyScore: 45,
          reviewStatus: "automated"
        }),
        nullifier: crypto.createHash("sha256").update("nullifier:scope-academic:002").digest("hex"),
        mod: undefined
      },
      {
        id: "rep-003",
        ref: "INC-483719",
        secret: "sec_c519d0aa",
        cat: "cat-institutional",
        body: "[Encrypted] Departmental budget allocation for assistive educational equipment diverted without student governance notice.",
        priority: "low",
        status: "action_taken",
        moderation: JSON.stringify({
          classification: "cleared",
          confidence: 0.91,
          policyVersion: "2026.4-standard",
          detectedSignals: ["Governance Review", "Resource Allocation"],
          urgencyScore: 30,
          reviewStatus: "human_reviewed"
        }),
        nullifier: crypto.createHash("sha256").update("nullifier:scope-inst:003").digest("hex"),
        mod: "mod-sec-02"
      }
    ];

    const insertRep = db.prepare(`
      INSERT INTO reports (
        id, reference, status_secret_hash, category_id, encrypted_body, priority, status,
        moderation_result, nullifier_hash, created_at, updated_at, assigned_moderator,
        audit_committed, audit_batch_id
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?)
    `);

    const commitments: string[] = [];
    for (const r of reports) {
      const secretHash = crypto.createHash("sha256").update(r.secret).digest("hex");
      insertRep.run(
        r.id, r.ref, secretHash, r.cat, r.body, r.priority, r.status,
        r.moderation, r.nullifier, now, now, r.mod || null, batchId
      );
      const commHash = crypto.createHash("sha256").update(`${r.ref}:${r.nullifier}`).digest("hex");
      commitments.push(commHash);
    }

    // Compute real pairwise Merkle Root
    const merkleTree = new MerkleTree(commitments);
    const merkleRoot = merkleTree.getRoot();

    db.prepare(`
      INSERT INTO audit_batches (
        id, sequence, merkle_root, report_count, status, contract_address,
        network, tx_hash, block_number, created_at, published_at
      ) VALUES (?, 1, ?, 3, 'published', ?, 'Sepolia Testnet', ?, 5894102, ?, ?)
    `).run(
      batchId, merkleRoot, env.contractAddress,
      "0x89abf721c056d814be953dc30e018d9f48ac123984570192837465abcedf1234",
      now, new Date(Date.now() - 3600 * 1000 * 24).toISOString()
    );

    const insertAuditRecord = db.prepare("INSERT INTO audit_records (id, batch_id, report_reference, commitment_hash, created_at) VALUES (?, ?, ?, ?, ?)");
    for (let i = 0; i < reports.length; i++) {
      insertAuditRecord.run(`ar-${i + 1}`, batchId, reports[i].ref, commitments[i], now);
    }
  }
}

  // Ensure any existing batch-101 has its Merkle root calculated with pairwise MerkleTree
  const existingBatch = db.prepare("SELECT id, merkle_root FROM audit_batches WHERE id = 'batch-101'").get() as any;
  if (existingBatch) {
    const records = db.prepare("SELECT commitment_hash FROM audit_records WHERE batch_id = 'batch-101'").all() as any[];
    if (records.length > 0) {
      const trueRoot = new MerkleTree(records.map(r => r.commitment_hash)).getRoot();
      if (existingBatch.merkle_root !== trueRoot) {
        db.prepare("UPDATE audit_batches SET merkle_root = ? WHERE id = 'batch-101'").run(trueRoot);
      }
    }
  }
}

export function closeDatabase(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}
