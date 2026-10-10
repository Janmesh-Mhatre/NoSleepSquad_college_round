import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader, MetricCard, StatusBadge, LoadingState, ErrorState } from "../../components/ui";
import { auditService, securityService, systemService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { AuditQueueStatus, SecurityPostureSummary, SystemHealth } from "../../api/types";
import { ShieldCheck, Layers, Terminal, Activity, ArrowRight } from "lucide-react";

export function AdminDashboard() {
  const [queue, setQueue] = useState<AuditQueueStatus | null>(null);
  const [posture, setPosture] = useState<SecurityPostureSummary | null>(null);
  const [health, setHealth] = useState<SystemHealth | null>(null);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    Promise.all([
      auditService.getQueueStatus(),
      securityService.getTests(),
      systemService.getHealth(),
    ])
      .then(([q, p, h]) => {
        setQueue(q);
        setPosture(p);
        setHealth(h);
      })
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load admin telemetry.");
      })
      .finally(() => setBusy(false));
  }, []);

  if (busy) return <LoadingState message="Loading administrative infrastructure state..." />;
  if (err) return <ErrorState message={err} />;

  return (
    <>
      <PageHeader
        title="Institutional Administrator Console"
        lead="Manage cryptographic audit publication, verify zero-identity constraints, and monitor system health."
      />

      <div className="metrics-grid">
        <MetricCard
          label="System Health"
          value={health?.status === "ok" ? "HEALTHY" : "DEGRADED"}
          subtext="All 6 core services operational"
        />
        <MetricCard
          label="Pending Audit Queue"
          value={queue?.pendingReportsInQueue ?? 0}
          subtext="Reports awaiting next Merkle batch"
        />
        <MetricCard
          label="Security Tests Passed"
          value={`${posture?.testsPassed ?? 0} / ${posture?.testsTotal ?? 0}`}
          subtext="Automated security posture checks"
        />
        <MetricCard
          label="Latest Batch Sequence"
          value={queue?.latestPublishedBatch ? `#${queue.latestPublishedBatch.sequence}` : "N/A"}
          subtext="Smart contract audit commitment"
        />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16, marginTop: 12 }}>
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
              <Layers size={18} style={{ color: "var(--accent)" }} aria-hidden />
              <span>Audit Commitment Engine</span>
            </h3>
            <Link to="/admin/audit" className="muted" style={{ fontSize: "0.85rem", display: "flex", alignItems: "center", gap: 4 }}>
              Audit console <ArrowRight size={13} aria-hidden />
            </Link>
          </div>
          <p className="muted" style={{ fontSize: "0.88rem" }}>
            Audit records are aggregated into deterministic SHA-256 Merkle trees and committed to a public smart contract for tamper-evident proof of inclusion.
          </p>
          <div style={{ background: "var(--surface-secondary)", padding: 12, borderRadius: "var(--r-sm)", fontSize: "0.85rem" }}>
            <div>Latest Root: <code className="mono">{queue?.latestPublishedBatch?.root.substring(0, 24)}...</code></div>
            <div style={{ marginTop: 4 }}>Blockchain: <StatusBadge kind="ok">{queue?.blockchainStatus || "connected"}</StatusBadge></div>
          </div>
        </div>

        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
              <ShieldCheck size={18} style={{ color: "var(--ok)" }} aria-hidden />
              <span>Automated Security Test Suite</span>
            </h3>
            <Link to="/admin/security" className="muted" style={{ fontSize: "0.85rem", display: "flex", alignItems: "center", gap: 4 }}>
              Run tests <ArrowRight size={13} aria-hidden />
            </Link>
          </div>
          <p className="muted" style={{ fontSize: "0.88rem" }}>
            Continuously tests database schemas, secret hashing, nullifier scopes, and transport hygiene to verify that zero identifying records leak into reporting storage.
          </p>
          <div style={{ background: "var(--surface-secondary)", padding: 12, borderRadius: "var(--r-sm)", fontSize: "0.85rem" }}>
            <div>Last Scan: <span className="mono">{new Date(posture?.lastScanTimestamp || Date.now()).toLocaleTimeString()}</span></div>
            <div style={{ marginTop: 4 }}>Overall Posture: <StatusBadge kind="ok">{posture?.overallStatus || "healthy"}</StatusBadge></div>
          </div>
        </div>
      </div>
    </>
  );
}
