import { useEffect, useState } from "react";
import { PageHeader, StepIndicator, PrivacyNotice, ErrorState, StatusBadge, LoadingState } from "../components/ui";
import { credentialService } from "../api/services";
import { ApiError } from "../api/client";
import { ShieldCheck, UserCheck, Key, RefreshCw, CheckCircle2, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";

export function Enroll() {
  const [step, setStep] = useState(0);
  const [memberRef, setMemberRef] = useState("demo-member-01");
  const [statusData, setStatusData] = useState<{
    registered: boolean;
    active: boolean;
    status: string;
    credentialRegistered: boolean;
    credentialStatus: string;
    expiresAt?: string;
  } | null>(null);
  const [commitmentRef, setCommitmentRef] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function loadStatus() {
    setBusy(true);
    setErr("");
    try {
      const res = await credentialService.getMembershipStatus(memberRef);
      setStatusData(res);
      if (res.active && res.credentialRegistered) {
        setStep(2); // Already fully enrolled
      } else if (res.active) {
        setStep(1); // Eligible, needs credential
      } else {
        setStep(0);
      }
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Failed to load membership status.");
    } finally {
      setBusy(false);
    }
  }

  useEffect(() => {
    loadStatus();
  }, [memberRef]);

  async function handleEnroll() {
    setBusy(true);
    setErr("");
    try {
      const res = await credentialService.enroll(memberRef);
      setCommitmentRef(res.credential.commitmentReference);
      setStep(2);
      await loadStatus();
    } catch (e) {
      setErr(e instanceof ApiError ? e.message : "Enrollment request failed.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 760, margin: "0 auto" }}>
      <PageHeader
        title="Verify Institutional Eligibility"
        lead="Establish your right to report without attaching your institutional identity to future submissions."
      />

      <StepIndicator
        steps={["Verify Eligibility", "Issue Credential", "Setup Confirmation"]}
        current={step}
      />

      <PrivacyNotice title="Identity Separation Guarantee">
        <p style={{ margin: 0, fontSize: "0.9rem" }}>
          Your institutional account confirms your active eligibility. Your student or employee ID is never submitted with or linked to your anonymous report payload.
        </p>
      </PrivacyNotice>

      <div className="card" style={{ marginTop: 24 }}>
        <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: 8 }}>
          <UserCheck size={18} style={{ color: "var(--accent)" }} aria-hidden />
          <span>Institutional Verification Gateway</span>
        </h3>

        <div style={{ margin: "16px 0" }}>
          <label htmlFor="member-ref" style={{ marginTop: 0 }}>
            Institutional Member Identifier (Demo SSO Persona)
          </label>
          <div className="field-hint">
            In production, this is acquired via your university SAML/OAuth Single Sign-On provider.
          </div>
          <div className="row" style={{ gap: 8 }}>
            <input
              id="member-ref"
              value={memberRef}
              onChange={(e) => setMemberRef(e.target.value)}
              disabled={busy}
              style={{ maxWidth: 360 }}
            />
            <button
              type="button"
              className="btn"
              onClick={loadStatus}
              disabled={busy}
            >
              <RefreshCw size={14} aria-hidden /> Refresh Status
            </button>
          </div>
        </div>

        {busy && <LoadingState message="Verifying institutional record..." />}

        {err && <ErrorState message={err} />}

        {statusData && (
          <div style={{ background: "var(--surface-secondary)", padding: 16, borderRadius: "var(--r-sm)", marginTop: 16 }}>
            <h4 style={{ margin: "0 0 10px" }}>Authoritative Backend State</h4>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))", gap: 12, fontSize: "0.88rem" }}>
              <div>
                <span className="muted">Membership Status: </span>
                <StatusBadge kind={statusData.active ? "ok" : statusData.status === "revoked" ? "danger" : "warn"}>
                  {statusData.status}
                </StatusBadge>
              </div>
              <div>
                <span className="muted">Credential Status: </span>
                <StatusBadge kind={statusData.credentialRegistered ? "ok" : "neutral"}>
                  {statusData.credentialStatus}
                </StatusBadge>
              </div>
              {statusData.expiresAt && (
                <div>
                  <span className="muted">Expiration: </span>
                  <span className="mono">{new Date(statusData.expiresAt).toLocaleDateString()}</span>
                </div>
              )}
            </div>
            {commitmentRef && (
              <div style={{ marginTop: 12, fontSize: "0.85rem" }}>
                <span className="muted">Commitment Digest: </span>
                <code className="mono">{commitmentRef}</code>
              </div>
            )}
          </div>
        )}

        <div style={{ marginTop: 24, display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 12 }}>
          {step === 0 && (
            <button
              type="button"
              className="btn primary"
              onClick={handleEnroll}
              disabled={busy || (statusData ? statusData.active : false)}
            >
              <Key size={15} aria-hidden /> Register & Issue Credential
            </button>
          )}

          {step === 1 && (
            <button
              type="button"
              className="btn primary"
              onClick={handleEnroll}
              disabled={busy}
            >
              <ShieldCheck size={15} aria-hidden /> Generate Privacy Credential
            </button>
          )}

          {step === 2 && (
            <div className="row" style={{ width: "100%", justifyContent: "space-between" }}>
              <div style={{ display: "flex", alignItems: "center", gap: 8, color: "var(--ok)", fontWeight: 500 }}>
                <CheckCircle2 size={18} aria-hidden />
                <span>Eligibility Confirmed. Credential Active.</span>
              </div>
              <Link to="/report" className="btn primary">
                Proceed to Submit Report <ArrowRight size={15} aria-hidden />
              </Link>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
