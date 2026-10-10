import { FormEvent, useEffect, useRef, useState } from "react";
import { useLocation, useNavigate, Link } from "react-router-dom";
import { PageHeader, StepIndicator, PrivacyNotice, ErrorState, StatusBadge, LoadingState } from "../components/ui";
import { reportService } from "../api/services";
import { ApiError } from "../api/client";
import type { ReportCategory, SubmitResult } from "../api/types";
import { Lock, ShieldCheck, Printer, CheckCircle, Search, ArrowRight, ArrowLeft } from "lucide-react";

const MIN = 20;
const MAX = 5000;

export function Report() {
  const [step, setStep] = useState(0);
  const [categories, setCategories] = useState<ReportCategory[]>([]);
  const [cat, setCat] = useState("");
  const [body, setBody] = useState("");
  const [ack, setAck] = useState(false);
  const [busy, setBusy] = useState(false);
  const [loadingCats, setLoadingCats] = useState(true);
  const [err, setErr] = useState("");

  const idempotencyKey = useRef(crypto.randomUUID());
  const nav = useNavigate();

  useEffect(() => {
    reportService
      .getCategories()
      .then((res) => {
        setCategories(res);
        if (res.length > 0 && !cat) {
          setCat(res[0].id);
        }
      })
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load reporting categories.");
      })
      .finally(() => setLoadingCats(false));
  }, []);

  const valid = body.trim().length >= MIN && body.length <= MAX;
  const selectedCategory = categories.find((c) => c.id === cat);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    try {
      const res = await reportService.submit(
        { categoryId: cat, body },
        idempotencyKey.current
      );
      // Pass via router state: not in URL, not in storage
      nav("/report/submitted", { state: res, replace: true });
    } catch (x) {
      setErr(x instanceof ApiError ? x.message : "Submission failed. Please try again.");
      setBusy(false);
    }
  }

  return (
    <div style={{ maxWidth: 780, margin: "0 auto" }}>
      <PageHeader
        title="Submit an Anonymous Institutional Report"
        lead="Your institutional identity is separated from this submission. Drafts exist exclusively in page memory."
      />

      <StepIndicator
        steps={["Category", "Concern Details", "Privacy Review", "Submit Securely"]}
        current={step}
      />

      {loadingCats ? (
        <LoadingState message="Connecting to secure gateway..." />
      ) : (
        <form onSubmit={submit} noValidate>
          {step === 0 && (
            <fieldset>
              <legend>Select Report Category</legend>
              <p className="muted" style={{ fontSize: "0.88rem", margin: "4px 0 16px" }}>
                Choose the domain that best fits your concern. This configures the topic-scoped duplicate prevention mechanism.
              </p>
              <div style={{ display: "grid", gap: 12 }}>
                {categories.map((c) => (
                  <label
                    key={c.id}
                    style={{
                      display: "flex",
                      alignItems: "flex-start",
                      gap: 12,
                      padding: 12,
                      border: `1px solid ${cat === c.id ? "var(--accent)" : "var(--border)"}`,
                      background: cat === c.id ? "var(--accent-subtle)" : "var(--surface)",
                      borderRadius: "var(--r-sm)",
                      cursor: "pointer",
                      margin: 0,
                    }}
                  >
                    <input
                      type="radio"
                      name="cat"
                      value={c.id}
                      checked={cat === c.id}
                      onChange={() => setCat(c.id)}
                      style={{ width: "auto", marginTop: 4 }}
                    />
                    <div style={{ flex: 1 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                        <strong style={{ fontSize: "0.98rem" }}>{c.name}</strong>
                        <StatusBadge kind={c.riskTier === "urgent" ? "danger" : c.riskTier === "elevated" ? "warn" : "neutral"}>
                          {c.riskTier}
                        </StatusBadge>
                      </div>
                      <div className="muted" style={{ fontSize: "0.85rem", marginTop: 4 }}>
                        {c.description}
                      </div>
                    </div>
                  </label>
                ))}
              </div>
            </fieldset>
          )}

          {step === 1 && (
            <div className="card">
              <label htmlFor="report-body" style={{ marginTop: 0 }}>
                Describe the Concern
              </label>
              <p id="body-hint" className="field-hint">
                Describe what happened, where and when it occurred, and what institutional resolution you seek. <strong>Avoid unnecessary self-identifying details</strong> (e.g. your specific dorm room, student ID, or personal schedule).
              </p>
              <textarea
                id="report-body"
                rows={12}
                value={body}
                maxLength={MAX}
                aria-describedby="body-hint body-count"
                onChange={(e) => setBody(e.target.value)}
                placeholder="Provide detailed, objective information regarding the incident or hazard..."
                style={{ resize: "vertical" }}
              />
              <div
                id="body-count"
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  fontSize: "0.82rem",
                  color: body.length < MIN ? "var(--danger)" : "var(--text-muted)",
                  marginTop: 6,
                }}
              >
                <span>
                  {body.length} / {MAX} characters (minimum {MIN} required)
                </span>
                <span className="muted">Draft stored in volatile memory only</span>
              </div>
            </div>
          )}

          {step === 2 && (
            <PrivacyNotice title="Pre-Submission Privacy & Cryptographic Verification">
              <div style={{ display: "grid", gap: 12, margin: "12px 0", fontSize: "0.90rem" }}>
                <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                  <div style={{ background: "rgba(16, 185, 129, 0.08)", padding: 12, borderRadius: "var(--r-sm)", border: "1px solid rgba(16, 185, 129, 0.2)" }}>
                    <strong style={{ color: "var(--ok)", display: "block", marginBottom: 6 }}>✓ What is NOT Submitted</strong>
                    <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.6 }}>
                      <li>Student / Employee ID</li>
                      <li>Name, email, or profile</li>
                      <li>IP address or browser fingerprint</li>
                      <li>Authentication session tokens</li>
                    </ul>
                  </div>
                  <div style={{ background: "rgba(99, 102, 241, 0.08)", padding: 12, borderRadius: "var(--r-sm)", border: "1px solid rgba(99, 102, 241, 0.2)" }}>
                    <strong style={{ color: "var(--accent)", display: "block", marginBottom: 6 }}>ℹ What IS Submitted</strong>
                    <ul style={{ margin: 0, paddingLeft: 18, lineHeight: 1.6 }}>
                      <li>Selected topic category</li>
                      <li>AES-256-GCM encrypted text</li>
                      <li>Topic-scoped ZK nullifier</li>
                      <li>Timestamp for Merkle batch</li>
                    </ul>
                  </div>
                </div>

                <div style={{ background: "var(--surface-secondary)", padding: 12, borderRadius: "var(--r-sm)", border: "1px solid var(--border)", fontSize: "0.86rem" }}>
                  <strong>Operational Limitations:</strong>
                  <p style={{ margin: "4px 0 0", color: "var(--text-muted)" }}>
                    Cryptographic proofs verify membership without linking identity. However, they cannot protect against personal names or unique identifying facts voluntarily written inside the report text. Network transit should use a trusted proxy or VPN for IP-level isolation.
                  </p>
                </div>
              </div>

              <label
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 10,
                  fontWeight: 500,
                  fontSize: "0.92rem",
                  cursor: "pointer",
                  marginTop: 16,
                  paddingTop: 12,
                  borderTop: "1px solid var(--border)",
                }}
              >
                <input
                  type="checkbox"
                  checked={ack}
                  onChange={(e) => setAck(e.target.checked)}
                  style={{ width: "auto", margin: 0 }}
                />
                <span>I have reviewed these privacy disclosures and confirm my text contains no accidental self-identifying details.</span>
              </label>
            </PrivacyNotice>
          )}

          {step === 3 && (
            <div className="card">
              <h3 style={{ marginTop: 0 }}>Review Submission Summary</h3>
              <div style={{ display: "grid", gap: 12, margin: "16px 0", fontSize: "0.92rem" }}>
                <div>
                  <span className="muted">Category: </span>
                  <strong>{selectedCategory?.name}</strong>
                </div>
                <div>
                  <span className="muted">Payload Length: </span>
                  <span className="mono">{body.length} characters</span>
                </div>
                <div>
                  <span className="muted">Identity Separation: </span>
                  <StatusBadge kind="ok">Verified Decoupled</StatusBadge>
                </div>
                <div>
                  <span className="muted">Audit Commitment: </span>
                  <StatusBadge kind="neutral">Queued for Merkle Batch</StatusBadge>
                </div>
              </div>
              <p className="muted" style={{ fontSize: "0.85rem", borderTop: "1px solid var(--border)", paddingTop: 12 }}>
                Upon clicking "Submit Report Securely", you will receive a random reference number and a secret key. You must save the secret key to track your report's status.
              </p>
            </div>
          )}

          {err && <ErrorState message={err} />}

          <div className="row" style={{ marginTop: 24, justifyContent: "space-between" }}>
            {step > 0 ? (
              <button
                type="button"
                className="btn"
                onClick={() => setStep(step - 1)}
                disabled={busy}
              >
                <ArrowLeft size={15} aria-hidden /> Back
              </button>
            ) : <div />}

            {step < 3 ? (
              <button
                type="button"
                className="btn primary"
                onClick={() => setStep(step + 1)}
                disabled={(step === 0 && !cat) || (step === 1 && !valid) || (step === 2 && !ack)}
              >
                Continue <ArrowRight size={15} aria-hidden />
              </button>
            ) : (
              <button type="submit" className="btn primary" disabled={busy}>
                <Lock size={15} aria-hidden />
                {busy ? "Encrypting & Submitting..." : "Submit Report Securely"}
              </button>
            )}
          </div>
        </form>
      )}
    </div>
  );
}

export function Submitted() {
  const loc = useLocation();
  const state = loc.state as SubmitResult | null;

  if (!state) {
    return (
      <div style={{ maxWidth: 680, margin: "0 auto" }}>
        <PageHeader
          title="No Submission in Context"
          lead="This confirmation is only accessible immediately after submitting a report."
        />
        <Link to="/report" className="btn primary">
          Return to Report Submission
        </Link>
      </div>
    );
  }

  return (
    <div style={{ maxWidth: 680, margin: "0 auto" }}>
      <PageHeader
        title="Report Successfully Submitted"
        lead="Your concern has been encrypted and recorded by the institutional reporting gateway."
      />

      <div className="card" style={{ borderLeft: "4px solid var(--ok)", marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--ok)", marginBottom: 12 }}>
          <CheckCircle size={22} aria-hidden />
          <strong style={{ fontSize: "1.1rem" }}>Submission Recorded</strong>
        </div>

        <div style={{ display: "grid", gap: 12, fontSize: "0.95rem" }}>
          <div>
            <span className="muted">Public Reference: </span>
            <span className="mono" style={{ fontWeight: 700, fontSize: "1.15rem" }}>
              {state.reference}
            </span>
          </div>

          <div>
            <span className="muted">Initial Status: </span>
            <StatusBadge kind="ok">{state.status}</StatusBadge>
          </div>

          {state.statusSecret && (
            <div style={{ background: "var(--surface-secondary)", padding: 14, borderRadius: "var(--r-sm)", border: "1px solid var(--border)" }}>
              <div className="muted" style={{ fontSize: "0.82rem", textTransform: "uppercase", letterSpacing: "0.04em" }}>
                Status Access Secret (Single-View Credential)
              </div>
              <div className="mono" style={{ fontSize: "1.1rem", fontWeight: 700, color: "var(--accent)", margin: "4px 0" }}>
                {state.statusSecret}
              </div>
              <div className="muted" style={{ fontSize: "0.82rem" }}>
                <strong>Important:</strong> Copy or print this secret now. The public reference alone cannot unlock status updates. To preserve your privacy, this secret is not saved in browser storage or cookies.
              </div>
            </div>
          )}
        </div>
      </div>

      <div className="row" style={{ gap: 12 }}>
        <button type="button" className="btn" onClick={() => window.print()}>
          <Printer size={15} aria-hidden /> Print Submission Receipt
        </button>
        <Link to="/report/status" className="btn primary">
          <Search size={15} aria-hidden /> Track Report Status
        </Link>
      </div>
    </div>
  );
}

const STATUS_ORDER = [
  "received",
  "under_review",
  "moderation_review",
  "assigned",
  "action_taken",
  "closed",
] as const;

export function Status() {
  const [ref, setRef] = useState("");
  const [sec, setSec] = useState("");
  const [res, setRes] = useState<{
    status: string;
    categoryName: string;
    createdAt: string;
    priority: string;
  } | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  async function lookup(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr("");
    setRes(null);
    try {
      const data = await reportService.status(ref.trim(), sec.trim());
      setRes(data);
    } catch (x) {
      setErr(x instanceof ApiError ? x.message : "Lookup failed.");
    } finally {
      setBusy(false);
    }
  }

  const currentIdx = res ? STATUS_ORDER.indexOf(res.status as any) : -1;

  return (
    <div style={{ maxWidth: 680, margin: "0 auto" }}>
      <PageHeader
        title="Check Report Status"
        lead="Enter your public reference and secret key to view authorized investigation progress."
      />

      <form onSubmit={lookup} className="card" style={{ marginBottom: 24 }}>
        <div style={{ marginBottom: 16 }}>
          <label htmlFor="ref-input" style={{ marginTop: 0 }}>
            Report Reference Number
          </label>
          <input
            id="ref-input"
            value={ref}
            placeholder="e.g. INC-849204"
            onChange={(e) => setRef(e.target.value)}
            className="mono"
            autoComplete="off"
            required
          />
        </div>

        <div style={{ marginBottom: 16 }}>
          <label htmlFor="sec-input" style={{ marginTop: 0 }}>
            Status Access Secret
          </label>
          <input
            id="sec-input"
            type="password"
            value={sec}
            placeholder="e.g. sec_a7f92e4b..."
            onChange={(e) => setSec(e.target.value)}
            className="mono"
            autoComplete="off"
            required
          />
          <div className="field-hint">
            Provided once at submission time. Plaintext secrets are never stored on the server.
          </div>
        </div>

        {err && <ErrorState message={err} />}

        <button
          type="submit"
          className="btn primary"
          disabled={busy || !ref || !sec}
          style={{ marginTop: 8 }}
        >
          <Search size={15} aria-hidden />
          {busy ? "Verifying Access Key..." : "Look Up Status"}
        </button>
      </form>

      {res && (
        <div className="card">
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 12 }}>
            <div>
              <h3 style={{ margin: 0 }}>Case Status: {ref}</h3>
              <p className="muted" style={{ fontSize: "0.85rem", marginTop: 4 }}>
                Category: <strong>{res.categoryName}</strong> · Submitted: {new Date(res.createdAt).toLocaleDateString()}
              </p>
            </div>
            <StatusBadge kind="ok">{res.status.replace(/_/g, " ")}</StatusBadge>
          </div>

          <div style={{ marginTop: 24 }}>
            <h4 style={{ marginBottom: 12 }}>Investigation Lifecycle</h4>
            <div style={{ display: "grid", gap: 8 }}>
              {STATUS_ORDER.map((s, idx) => {
                const isPassed = currentIdx >= idx;
                const isCurrent = currentIdx === idx;
                return (
                  <div
                    key={s}
                    style={{
                      display: "flex",
                      alignItems: "center",
                      gap: 12,
                      padding: "8px 12px",
                      borderRadius: "var(--r-sm)",
                      background: isCurrent ? "var(--accent-subtle)" : "var(--surface)",
                      border: `1px solid ${isCurrent ? "var(--accent)" : isPassed ? "var(--border)" : "var(--border-subtle)"}`,
                      opacity: isPassed ? 1 : 0.5,
                    }}
                  >
                    <div
                      style={{
                        width: 22,
                        height: 22,
                        borderRadius: "50%",
                        background: isPassed ? "var(--accent)" : "var(--surface-tertiary)",
                        color: "#fff",
                        display: "flex",
                        alignItems: "center",
                        justifyContent: "center",
                        fontSize: "0.75rem",
                        fontWeight: 700,
                      }}
                    >
                      {idx + 1}
                    </div>
                    <div style={{ flex: 1, textTransform: "capitalize", fontSize: "0.9rem", fontWeight: isCurrent ? 600 : 400 }}>
                      {s.replace(/_/g, " ")}
                    </div>
                    {isCurrent && (
                      <span className="brand-badge" style={{ fontSize: "0.7rem", color: "var(--accent)" }}>
                        Current Stage
                      </span>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
