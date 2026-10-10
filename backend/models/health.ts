export interface HealthResponse {
  status: "ok" | "degraded" | "unavailable";
  service: string;
  version: string;
  timestamp: string;
  components: {
    api: { state: "operational" | "degraded" | "unavailable"; detail?: string };
    database: { state: "operational" | "degraded" | "unavailable"; detail?: string };
    membershipService: { state: "operational" | "degraded" | "unavailable"; detail?: string };
    moderationEngine: { state: "operational" | "degraded" | "unavailable"; detail?: string };
    auditBatcher: { state: "operational" | "degraded" | "unavailable"; detail?: string };
    blockchain: { state: "operational" | "not_configured" | "unavailable"; detail?: string };
  };
}
