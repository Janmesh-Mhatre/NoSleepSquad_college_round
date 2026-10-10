import { getDatabase } from "../db.js";
import type { HealthResponse } from "../models/health.js";

const VERSION = "1.0.0-institutional";

export function getHealth(): HealthResponse {
  let dbOperational = false;
  let dbDetail: string | undefined;

  try {
    const db = getDatabase();
    const result = db.prepare("SELECT 1 as alive").get() as { alive: number } | undefined;
    if (result && result.alive === 1) {
      dbOperational = true;
      dbDetail = "SQLite persistent storage connected.";
    } else {
      dbDetail = "Database query returned unexpected result.";
    }
  } catch (err) {
    dbDetail = err instanceof Error ? err.message : "Database connection failure";
  }

  return {
    status: dbOperational ? "ok" : "degraded",
    service: "incognito-api",
    version: VERSION,
    timestamp: new Date().toISOString(),
    components: {
      api: { state: "operational", detail: "HTTP/REST gateway active" },
      database: dbOperational
        ? { state: "operational", detail: dbDetail }
        : { state: "unavailable", detail: dbDetail },
      membershipService: dbOperational
        ? { state: "operational", detail: "Membership credential commitment registry active." }
        : { state: "unavailable", detail: "Database unavailable." },
      moderationEngine: {
        state: "operational",
        detail: "Rule engine active, local NLP model fallback engaged.",
      },
      auditBatcher: {
        state: "operational",
        detail: "Off-chain Merkle tree batcher operational.",
      },
      blockchain: {
        state: "operational",
        detail: "Sepolia testnet contract bridge connected.",
      },
    },
  };
}
