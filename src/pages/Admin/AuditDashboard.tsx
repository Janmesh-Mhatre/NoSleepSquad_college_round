import { useEffect, useState } from "react";
import { PageHeader, StatusBadge, LoadingState, ErrorState } from "../../components/ui";
import { AuditPipelineDiagram } from "../../components/AuditPipelineDiagram";
import { auditService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { AuditBatch, AuditVerificationResult } from "../../api/types";
import { CheckCircle2, ShieldAlert, RefreshCw } from "lucide-react";

export function AuditDashboard() {
  const [batches, setBatches] = useState<AuditBatch[]>([]);
  const [verifyResult, setVerifyResult] = useState<AuditVerificationResult | null>(null);
  const [verifyingId, setVerifyingId] = useState<string | null>(null);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");

  function loadBatches() {
    setBusy(true);
    setErr("");
    auditService
      .getBatches()
      .then(setBatches)
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load audit batches.");
      })
      .finally(() => setBusy(false));
  }

  useEffect(() => {
    loadBatches();
  }, []);

  async function verifyBatch(batchId: string) {
    setVerifyingId(batchId);
    setVerifyResult(null);
    try {
      const res = await auditService.verifyBatch(batchId);
      setVerifyResult(res);
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Verification failed.");
    } finally {
      setVerifyingId(null);
    }
  }

  if (busy) return <LoadingState message="Fetching blockchain audit batches..." />;
  if (err) return <ErrorState message={err} onRetry={loadBatches} />;

  return (
    <>
      <PageHeader
        title="Tamper-Evident Audit & Blockchain Commitments"
        lead="Inspect deterministic Merkle trees and verify cryptographic commitments published to the smart contract."
        actions={
          <button type="button" className="btn sm" onClick={loadBatches} disabled={busy}>
            <RefreshCw size={13} aria-hidden /> Refresh Batches
          </button>
        }
      />

      <AuditPipelineDiagram />

      {verifyResult && (
        <div
          className="card"
          style={{
            borderLeft: `4px solid ${verifyResult.matches ? "var(--ok)" : "var(--danger)"}`,
            marginBottom: 20,
            background: "var(--surface-secondary)",
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            {verifyResult.matches ? (
              <CheckCircle2 size={18} style={{ color: "var(--ok)" }} aria-hidden />
            ) : (
              <ShieldAlert size={18} style={{ color: "var(--danger)" }} aria-hidden />
            )}
            <strong style={{ fontSize: "1rem" }}>
              Batch {verifyResult.batchId} Cryptographic Verification {verifyResult.matches ? "MATCH" : "MISMATCH"}
            </strong>
          </div>
          <div style={{ display: "grid", gap: 6, fontSize: "0.88rem" }}>
            <div>
              <span className="muted">Batch ID: </span>
              <code className="mono">{verifyResult.batchId}</code>
            </div>
            <div>
              <span className="muted">Calculated Merkle Root: </span>
              <code className="mono">{verifyResult.calculatedMerkleRoot}</code>
            </div>
            <div>
              <span className="muted">On-Chain Contract Root: </span>
              <code className="mono">{verifyResult.publishedMerkleRoot}</code>
            </div>
            <div>
              <span className="muted">Block Number: </span>
              <span className="mono">{verifyResult.blockNumber ? `#${verifyResult.blockNumber}` : "Pending on-chain block confirmation"}</span>
            </div>
            <div>
              <span className="muted">Transaction Hash: </span>
              {verifyResult.txHash ? (
                <code className="mono">{verifyResult.txHash}</code>
              ) : (
                <span className="muted">Not published to RPC (offline/pending retry)</span>
              )}
            </div>
            <div>
              <span className="muted">Verification Timestamp: </span>
              <span className="muted">{verifyResult.timestamp}</span>
            </div>
          </div>
        </div>
      )}

      <div className="card">
        <h3 style={{ marginTop: 0, marginBottom: 12 }}>Committed Merkle Audit Batches</h3>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Batch ID</th>
                <th>Merkle Root (SHA-256)</th>
                <th>Record Count</th>
                <th>Publication State</th>
                <th>Block #</th>
                <th>Tx Hash</th>
                <th>Network</th>
                <th>Published At</th>
                <th>Reconciliation</th>
              </tr>
            </thead>
            <tbody>
              {batches.map((b) => (
                <tr key={b.id}>
                  <td className="mono" style={{ fontWeight: 600 }}>{b.id}</td>
                  <td className="mono" style={{ fontSize: "0.82rem" }} title={b.merkleRoot}>
                    {b.merkleRoot.substring(0, 16)}...{b.merkleRoot.substring(b.merkleRoot.length - 8)}
                  </td>
                  <td>{b.reportCount} reports</td>
                  <td>
                    <StatusBadge kind={b.status === "published" || b.status === "verified" || b.status === "confirmed" ? "ok" : b.status === "pending" || b.status === "pending_retry" ? "pending" : "warn"}>
                      {b.status}
                    </StatusBadge>
                  </td>
                  <td className="mono" style={{ fontSize: "0.85rem" }}>
                    {b.blockNumber ? `#${b.blockNumber}` : "—"}
                  </td>
                  <td className="mono" style={{ fontSize: "0.80rem" }} title={b.txHash || ""}>
                    {b.txHash ? `${b.txHash.substring(0, 10)}...${b.txHash.substring(b.txHash.length - 6)}` : "—"}
                  </td>
                  <td className="muted" style={{ fontSize: "0.85rem" }}>{b.network}</td>
                  <td className="muted" style={{ fontSize: "0.82rem" }}>
                    {b.publishedAt ? new Date(b.publishedAt).toLocaleDateString() : "Pending"}
                  </td>
                  <td>
                    <button
                      type="button"
                      className="btn sm"
                      onClick={() => verifyBatch(b.id)}
                      disabled={verifyingId === b.id}
                    >
                      {verifyingId === b.id ? "Reconciling..." : "Reconcile"}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </>
  );
}
