import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader, MetricCard, StatusBadge, LoadingState, ErrorState } from "../../components/ui";
import { reportService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { ModeratorMetrics, ModeratorReportSummary } from "../../api/types";
import { Inbox, AlertTriangle, CheckCircle, Shield, FileText, ArrowRight } from "lucide-react";

export function ModeratorDashboard() {
  const [metrics, setMetrics] = useState<ModeratorMetrics | null>(null);
  const [recentReports, setRecentReports] = useState<ModeratorReportSummary[]>([]);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    Promise.all([reportService.getMetrics(), reportService.getModeratorReports({ status: "all" })])
      .then(([m, reps]) => {
        setMetrics(m);
        setRecentReports(reps.slice(0, 5));
      })
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load moderator metrics.");
      })
      .finally(() => setBusy(false));
  }, []);

  if (busy) return <LoadingState message="Loading moderator console metrics..." />;
  if (err) return <ErrorState message={err} />;
  if (!metrics) return null;

  return (
    <>
      <PageHeader
        title="Moderation Operations Console"
        lead="Review anonymous concerns, evaluate AI safety signals, and enforce institutional integrity."
        actions={
          <Link to="/moderator/reports" className="btn primary sm">
            <Inbox size={14} aria-hidden /> Open Report Queue
          </Link>
        }
      />

      <div className="metrics-grid">
        <MetricCard label="Total Received Reports" value={metrics.totalReports} subtext="All time anonymous reports" />
        <MetricCard label="Awaiting Initial Review" value={metrics.awaitingReview} subtext="Pending moderator triage" />
        <MetricCard label="In Investigation" value={metrics.inInvestigation} subtext="Under active inquiry" />
        <MetricCard label="Resolved / Closed" value={metrics.resolved} subtext="Action taken or archived" />
        <MetricCard label="Flagged by Safety Rules" value={metrics.flaggedByModeration} subtext="Urgent / elevated signals" />
        <MetricCard label="Committed to Audit Trail" value={metrics.auditCommitted} subtext="Anchored to Merkle tree" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr", gap: 24, marginTop: 12 }}>
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 16 }}>
            <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
              <FileText size={18} style={{ color: "var(--accent)" }} aria-hidden />
              <span>Recent Queue Submissions</span>
            </h3>
            <Link to="/moderator/reports" className="muted" style={{ fontSize: "0.85rem", display: "flex", alignItems: "center", gap: 4 }}>
              View all queue <ArrowRight size={13} aria-hidden />
            </Link>
          </div>

          <div className="table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Reference</th>
                  <th>Category</th>
                  <th>Status</th>
                  <th>Priority</th>
                  <th>Safety Signal</th>
                  <th>Received</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentReports.map((r) => (
                  <tr key={r.id}>
                    <td className="mono" style={{ fontWeight: 600 }}>{r.reference}</td>
                    <td>{r.categoryName}</td>
                    <td>
                      <StatusBadge kind={r.status === "received" ? "warn" : r.status === "closed" ? "neutral" : "ok"}>
                        {r.status.replace(/_/g, " ")}
                      </StatusBadge>
                    </td>
                    <td>
                      <span className={`badge ${r.priority === "high" || r.priority === "critical" ? "danger" : r.priority === "medium" ? "warn" : "neutral"}`}>
                        {r.priority}
                      </span>
                    </td>
                    <td>
                      <span className="muted" style={{ fontSize: "0.82rem" }}>
                        {r.moderationResult.detectedSignals.slice(0, 2).join(", ")}
                      </span>
                    </td>
                    <td className="muted" style={{ fontSize: "0.82rem" }}>
                      {new Date(r.createdAt).toLocaleDateString()}
                    </td>
                    <td>
                      <Link to={`/moderator/reports/${r.id}`} className="btn sm">
                        Review
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </>
  );
}
