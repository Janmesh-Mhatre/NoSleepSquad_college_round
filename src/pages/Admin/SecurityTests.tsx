import { useEffect, useState } from "react";
import { PageHeader, StatusBadge, LoadingState, ErrorState, MetricCard } from "../../components/ui";
import { securityService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { SecurityPostureSummary } from "../../api/types";
import { ShieldCheck, Play, CheckCircle2, AlertTriangle, XCircle, Clock } from "lucide-react";

export function SecurityTests() {
  const [posture, setPosture] = useState<SecurityPostureSummary | null>(null);
  const [busy, setBusy] = useState(true);
  const [running, setRunning] = useState(false);
  const [err, setErr] = useState("");

  function loadTests() {
    setBusy(true);
    setErr("");
    securityService
      .getTests()
      .then(setPosture)
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load security posture.");
      })
      .finally(() => setBusy(false));
  }

  useEffect(() => {
    loadTests();
  }, []);

  async function handleRunTests() {
    setRunning(true);
    setErr("");
    try {
      const updated = await securityService.runTests();
      setPosture(updated);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to execute automated security tests.");
    } finally {
      setRunning(false);
    }
  }

  if (busy) return <LoadingState message="Querying live security assertions..." />;
  if (err) return <ErrorState message={err} onRetry={loadTests} />;
  if (!posture) return null;

  return (
    <>
      <PageHeader
        title="Automated Privacy & Security Verification"
        lead="Live technical test runner confirming schema constraints, zero-PII isolation, and cryptographic hashing."
        actions={
          <button
            type="button"
            className="btn primary sm"
            onClick={handleRunTests}
            disabled={running}
          >
            <Play size={13} aria-hidden />
            {running ? "Executing Test Suite..." : "Execute Test Suite"}
          </button>
        }
      />

      <div className="metrics-grid">
        <MetricCard label="Security Posture" value={posture.overallStatus.toUpperCase()} subtext="Automated integrity checks" />
        <MetricCard label="Checks Passed" value={`${posture.testsPassed} / ${posture.testsTotal}`} subtext="Zero regression tolerance" />
        <MetricCard label="Scan Timestamp" value={new Date(posture.lastScanTimestamp).toLocaleTimeString()} subtext="System audit run time" />
      </div>

      <div className="card" style={{ marginBottom: 20 }}>
        <h3 style={{ marginTop: 0, marginBottom: 16 }}>Live Privacy & Boundary Assertions</h3>
        <div style={{ display: "grid", gap: 12 }}>
          {posture.results.map((t) => (
            <div
              key={t.id}
              style={{
                padding: "14px 16px",
                border: "1px solid var(--border)",
                borderRadius: "var(--r-sm)",
                background: "var(--surface)",
                display: "flex",
                justifyContent: "space-between",
                alignItems: "flex-start",
                gap: 16,
                flexWrap: "wrap",
              }}
            >
              <div style={{ flex: 1, minWidth: 260 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 4 }}>
                  {t.status === "passed" ? (
                    <CheckCircle2 size={16} style={{ color: "var(--ok)" }} aria-hidden />
                  ) : t.status === "warning" ? (
                    <AlertTriangle size={16} style={{ color: "var(--warn)" }} aria-hidden />
                  ) : (
                    <XCircle size={16} style={{ color: "var(--danger)" }} aria-hidden />
                  )}
                  <strong style={{ fontSize: "0.95rem" }}>{t.name}</strong>
                  <span className="brand-badge">{t.category.replace(/_/g, " ")}</span>
                </div>
                <p className="muted" style={{ margin: "4px 0 0", fontSize: "0.85rem" }}>
                  {t.details}
                </p>
              </div>

              <div style={{ display: "flex", alignItems: "center", gap: 12 }}>
                <span className="mono muted" style={{ fontSize: "0.8rem" }}>
                  {t.durationMs}ms
                </span>
                <StatusBadge kind={t.status === "passed" ? "ok" : t.status === "warning" ? "warn" : "danger"}>
                  {t.status}
                </StatusBadge>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="card" style={{ borderLeft: "4px solid var(--accent)", background: "var(--surface-secondary)" }}>
        <h4 style={{ margin: "0 0 8px", color: "var(--text)" }}>Active Security & Cryptographic Advisories</h4>
        <ul style={{ paddingLeft: 20, margin: 0, fontSize: "0.88rem", lineHeight: 1.6 }} className="muted">
          {posture.securityAdvisories.map((adv, idx) => (
            <li key={idx}>{adv}</li>
          ))}
        </ul>
      </div>
    </>
  );
}
