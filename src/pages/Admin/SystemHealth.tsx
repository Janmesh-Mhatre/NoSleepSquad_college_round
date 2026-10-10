import { useEffect, useState } from "react";
import { PageHeader, StatusBadge, LoadingState, ErrorState, MetricCard } from "../../components/ui";
import { systemService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { SystemHealth } from "../../api/types";
import { Activity, RefreshCw, CheckCircle, Server, Database, Key, Shield, Layers } from "lucide-react";

export function SystemHealth() {
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");

  function loadHealth() {
    setBusy(true);
    setErr("");
    systemService
      .getHealth()
      .then(setHealth)
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load system health.");
      })
      .finally(() => setBusy(false));
  }

  useEffect(() => {
    loadHealth();
  }, []);

  if (busy) return <LoadingState message="Polling system component status..." />;
  if (err) return <ErrorState message={err} onRetry={loadHealth} />;
  if (!health) return null;

  const components = [
    { name: "HTTP / API Gateway", icon: Server, data: health.components.api },
    { name: "SQLite Persistence Engine", icon: Database, data: health.components.database },
    { name: "Membership Credential Registry", icon: Key, data: health.components.membershipService },
    { name: "Rule & Safety Moderation Engine", icon: Shield, data: health.components.moderationEngine },
    { name: "Off-chain Audit Merkle Batcher", icon: Layers, data: health.components.auditBatcher },
    { name: "Smart Contract Blockchain Bridge", icon: Activity, data: health.components.blockchain },
  ];

  return (
    <>
      <PageHeader
        title="System Infrastructure Health"
        lead={`Service: ${health.service} v${health.version} · Authoritative status probes`}
        actions={
          <button type="button" className="btn sm" onClick={loadHealth} disabled={busy}>
            <RefreshCw size={13} aria-hidden /> Probe Services
          </button>
        }
      />

      <div className="metrics-grid">
        <MetricCard label="Gateway State" value={health.status === "ok" ? "OPERATIONAL" : "DEGRADED"} subtext="HTTP 200 OK" />
        <MetricCard label="Service Version" value={`v${health.version}`} subtext="Release branch" />
        <MetricCard label="Probe Timestamp" value={new Date(health.timestamp).toLocaleTimeString()} subtext="UTC timestamp" />
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0, marginBottom: 16 }}>Component Readiness Probes</h3>
        <div style={{ display: "grid", gap: 12 }}>
          {components.map((c) => {
            const Icon = c.icon;
            const isOp = c.data?.state === "operational";
            return (
              <div
                key={c.name}
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "center",
                  padding: "12px 16px",
                  borderRadius: "var(--r-sm)",
                  border: "1px solid var(--border)",
                  background: "var(--surface)",
                  flexWrap: "wrap",
                  gap: 12,
                }}
              >
                <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                  <Icon size={18} style={{ color: isOp ? "var(--accent)" : "var(--warn)" }} aria-hidden />
                  <div>
                    <strong style={{ fontSize: "0.95rem" }}>{c.name}</strong>
                    {c.data?.detail && (
                      <div className="muted" style={{ fontSize: "0.82rem", marginTop: 2 }}>
                        {c.data.detail}
                      </div>
                    )}
                  </div>
                </div>
                <StatusBadge kind={isOp ? "ok" : "warn"}>
                  {c.data?.state || "unknown"}
                </StatusBadge>
              </div>
            );
          })}
        </div>
      </div>
    </>
  );
}
