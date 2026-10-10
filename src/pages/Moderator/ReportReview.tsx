import { useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { PageHeader, StatusBadge, LoadingState, ErrorState, ConfirmationModal } from "../../components/ui";
import { reportService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { ReportDetail, ReportStatus } from "../../api/types";
import { ArrowLeft, Shield, AlertTriangle, CheckCircle, Clock, UserCheck, Lock, FileCheck } from "lucide-react";

export function ReportReview() {
  const { id } = useParams<{ id: string }>();
  const [report, setReport] = useState<ReportDetail | null>(null);
  const [busy, setBusy] = useState(true);
  const [actionBusy, setActionBusy] = useState(false);
  const [err, setErr] = useState("");
  const [actionErr, setActionErr] = useState("");

  // Action form state
  const [selectedAction, setSelectedAction] = useState<"confirm" | "reclassify" | "escalate" | "request_review" | "close">("confirm");
  const [actionReason, setActionReason] = useState("");
  const [newStatusSelect, setNewStatusSelect] = useState<ReportStatus>("under_review");

  function loadReport() {
    if (!id) return;
    setBusy(true);
    setErr("");
    reportService
      .getReportById(id)
      .then((data) => {
        if (!data) throw new Error("Report not found.");
        setReport(data);
      })
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load report detail.");
      })
      .finally(() => setBusy(false));
  }

  useEffect(() => {
    loadReport();
  }, [id]);

  async function handleActionSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!report || !actionReason.trim()) return;
    setActionBusy(true);
    setActionErr("");

    try {
      await reportService.applyAction(report.id, {
        action: selectedAction,
        reason: actionReason,
        moderatorId: "mod-investigator-01",
        newStatus: selectedAction === "reclassify" ? newStatusSelect : undefined,
      });
      setActionReason("");
      loadReport();
    } catch (e) {
      setActionErr(e instanceof ApiError ? e.message : "Failed to execute moderation action.");
    } finally {
      setActionBusy(false);
    }
  }

  if (busy) return <LoadingState message="Loading decrypted case record..." />;
  if (err) return <ErrorState message={err} />;
  if (!report) return <ErrorState message="Report record could not be found." />;

  return (
    <>
      <div style={{ marginBottom: 16 }}>
        <Link to="/moderator/reports" className="muted" style={{ display: "inline-flex", alignItems: "center", gap: 6, fontSize: "0.88rem" }}>
          <ArrowLeft size={14} aria-hidden /> Back to Report Queue
        </Link>
      </div>

      <PageHeader
        title={`Report Review: ${report.reference}`}
        lead={`Category: ${report.categoryName} · Recorded: ${new Date(report.createdAt).toLocaleString()}`}
        actions={
          <StatusBadge kind={report.status === "received" ? "warn" : report.status === "closed" ? "neutral" : "ok"}>
            {report.status.replace(/_/g, " ")}
          </StatusBadge>
        }
      />

      <div className="two-panel">
        {/* Left Panel: Anonymous Report Content & History */}
        <div style={{ display: "grid", gap: 20 }}>
          <div className="card">
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <h3 style={{ margin: 0, display: "flex", alignItems: "center", gap: 8 }}>
                <Lock size={16} style={{ color: "var(--accent)" }} aria-hidden />
                <span>Encrypted Report Payload</span>
              </h3>
              <span className="brand-badge">AES-256-GCM Decrypted</span>
            </div>
            <div
              style={{
                background: "var(--surface-secondary)",
                padding: 16,
                borderRadius: "var(--r-sm)",
                border: "1px solid var(--border)",
                lineHeight: 1.7,
                whiteSpace: "pre-wrap",
                fontSize: "0.95rem",
              }}
            >
              {report.encryptedBody.replace(/^\[AES-256-GCM Encrypted\]\s*/, "")}
            </div>
            <div style={{ marginTop: 12, display: "flex", justifyContent: "space-between", fontSize: "0.82rem" }} className="muted">
              <span>Audit Anchored: {report.auditCommitted ? "Yes (Merkle Batch)" : "Pending next batch"}</span>
              <span>Nullifier: Validated Unique</span>
            </div>
          </div>

          {/* Historical Actions & Audit Trail */}
          <div className="card">
            <h3 style={{ marginTop: 0, marginBottom: 12 }}>Moderation Case Timeline</h3>
            {report.actions.length === 0 ? (
              <p className="muted" style={{ fontSize: "0.88rem", margin: 0 }}>
                No moderator interventions recorded yet. This report is awaiting initial triage.
              </p>
            ) : (
              <div style={{ display: "grid", gap: 12 }}>
                {report.actions.map((act) => (
                  <div
                    key={act.id}
                    style={{
                      padding: "10px 14px",
                      borderRadius: "var(--r-sm)",
                      border: "1px solid var(--border-subtle)",
                      background: "var(--surface-secondary)",
                      fontSize: "0.88rem",
                    }}
                  >
                    <div style={{ display: "flex", justifyContent: "space-between", marginBottom: 4 }}>
                      <strong style={{ textTransform: "capitalize" }}>{act.action.replace(/_/g, " ")}</strong>
                      <span className="muted" style={{ fontSize: "0.8rem" }}>
                        {new Date(act.createdAt).toLocaleString()}
                      </span>
                    </div>
                    <div className="muted" style={{ fontSize: "0.85rem", marginBottom: 4 }}>
                      Transition: <code>{act.previousStatus}</code> → <code>{act.newStatus}</code> by <code>{act.moderatorId}</code>
                    </div>
                    <div style={{ fontStyle: "italic", color: "var(--text)" }}>"{act.reason}"</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* Right Panel: AI Signals & Action Controls */}
        <div style={{ display: "grid", gap: 20 }}>
          {/* AI Moderation Signals */}
          <div className="card" style={{ borderLeft: "4px solid var(--warn)" }}>
            <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: 8 }}>
              <Shield size={16} style={{ color: "var(--warn)" }} aria-hidden />
              <span>AI Moderation Evaluation</span>
            </h3>
            <div style={{ display: "grid", gap: 8, fontSize: "0.88rem" }}>
              <div>
                <span className="muted">Safety Classification: </span>
                <StatusBadge kind={report.moderationResult.classification === "cleared" ? "ok" : report.moderationResult.classification === "escalated" ? "danger" : "warn"}>
                  {report.moderationResult.classification}
                </StatusBadge>
              </div>
              <div>
                <span className="muted">Model Confidence: </span>
                <strong className="mono">{Math.round(report.moderationResult.confidence * 100)}%</strong>
              </div>
              <div>
                <span className="muted">Urgency Score: </span>
                <span className="mono" style={{ fontWeight: 600 }}>{report.moderationResult.urgencyScore} / 100</span>
              </div>
              <div>
                <span className="muted">Policy Version: </span>
                <span className="mono">{report.moderationResult.policyVersion}</span>
              </div>
              <div>
                <span className="muted">Detected Safety Signals: </span>
                <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginTop: 4 }}>
                  {report.moderationResult.detectedSignals.map((sig) => (
                    <span key={sig} className="badge neutral">
                      {sig}
                    </span>
                  ))}
                </div>
              </div>
            </div>
          </div>

          {/* Action Execution Panel */}
          <form onSubmit={handleActionSubmit} className="card">
            <h3 style={{ marginTop: 0, marginBottom: 12 }}>Execute Moderation Action</h3>

            <div style={{ marginBottom: 14 }}>
              <label htmlFor="action-select" style={{ marginTop: 0 }}>Select Action</label>
              <select
                id="action-select"
                value={selectedAction}
                onChange={(e) => setSelectedAction(e.target.value as any)}
                disabled={actionBusy}
              >
                <option value="confirm">Confirm Initial Review (Under Review)</option>
                <option value="escalate">Escalate Case (Moderation Review)</option>
                <option value="request_review">Assign to Institutional Ombudsman</option>
                <option value="reclassify">Reclassify Status Manually</option>
                <option value="close">Close & Archive Investigation</option>
              </select>
            </div>

            {selectedAction === "reclassify" && (
              <div style={{ marginBottom: 14 }}>
                <label htmlFor="new-status-select" style={{ marginTop: 0 }}>Target Status</label>
                <select
                  id="new-status-select"
                  value={newStatusSelect}
                  onChange={(e) => setNewStatusSelect(e.target.value as any)}
                  disabled={actionBusy}
                >
                  <option value="received">Received</option>
                  <option value="under_review">Under Review</option>
                  <option value="moderation_review">Moderation Review</option>
                  <option value="assigned">Assigned</option>
                  <option value="action_taken">Action Taken</option>
                  <option value="closed">Closed</option>
                </select>
              </div>
            )}

            <div style={{ marginBottom: 14 }}>
              <label htmlFor="reason-input" style={{ marginTop: 0 }}>Action Reason (Required for Audit Trail)</label>
              <textarea
                id="reason-input"
                rows={4}
                value={actionReason}
                onChange={(e) => setActionReason(e.target.value)}
                placeholder="Detail rationale for this decision (min 5 chars)..."
                disabled={actionBusy}
                required
              />
            </div>

            {actionErr && <ErrorState message={actionErr} />}

            <button
              type="submit"
              className="btn primary"
              style={{ width: "100%", marginTop: 8 }}
              disabled={actionBusy || actionReason.trim().length < 5}
            >
              <FileCheck size={15} aria-hidden />
              {actionBusy ? "Recording Decision..." : "Apply & Commit Decision"}
            </button>
          </form>
        </div>
      </div>
    </>
  );
}
