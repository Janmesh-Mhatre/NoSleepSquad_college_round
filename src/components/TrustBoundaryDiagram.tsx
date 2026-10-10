import { ArrowDown, Eye, EyeOff, ShieldCheck, Database, Key, Lock, Layers } from "lucide-react";

const STAGES = [
  {
    name: "01. Institutional Identity & Verification",
    service: "Identity Service",
    icon: Key,
    boundary: "Institutional Identity Domain",
    sees: "Student ID, Institutional SSO credentials, Enrollment status",
    cannotSee: "Report content, draft tokens, or anonymous identifiers",
    description: "Authenticates your institutional affiliation without linking to any report submissions.",
  },
  {
    name: "02. Privacy-Preserving Credential",
    service: "Credential Issuer",
    icon: ShieldCheck,
    boundary: "Cryptographic Commitment Gateway",
    sees: "Eligibility verification outcome, commitment registration",
    cannotSee: "Report content, topic scope, or report timing",
    description: "Issues a scoped cryptographic commitment validating eligibility.",
  },
  {
    name: "03. Anonymous Reporting Gateway",
    service: "Reporting Service",
    icon: Lock,
    boundary: "Anonymous Submission Gateway",
    sees: "Report content, chosen category, topic-scoped nullifier proof",
    cannotSee: "Student ID, email, name, IP address, device fingerprints",
    description: "Verifies the anonymous proof and accepts report payload with zero identity metadata.",
  },
  {
    name: "04. AI Moderation & Encrypted Storage",
    service: "Security & Moderation Engine",
    icon: Database,
    boundary: "Restricted Operational Core",
    sees: "Sanitized report text, rule classification, priority signals",
    cannotSee: "Institutional identity or correlation across report topics",
    description: "Evaluates safety signals and securely encrypts payload at rest (AES-256-GCM).",
  },
  {
    name: "05. Audit Trail & Blockchain Commitment",
    service: "Audit Batcher & Smart Contract",
    icon: Layers,
    boundary: "Public Tamper-Evident Ledger",
    sees: "Merkle root commitments, transaction hash, block sequence",
    cannotSee: "Report text, reporter identity, or plaintext secrets",
    description: "Commits cryptographic Merkle roots to public testnet for tamper-evident inclusion proofs.",
  },
];

export function TrustBoundaryDiagram() {
  return (
    <section className="tb" aria-label="Cryptographic Trust Boundaries and System Architecture">
      {STAGES.map((s, idx) => {
        const Icon = s.icon;
        return (
          <div key={s.name} style={{ display: "grid", gap: 8 }}>
            <div className="tb-node" tabIndex={0} style={{ position: "relative" }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 8 }}>
                <h3 style={{ margin: 0, fontSize: "1.02rem" }}>
                  <Icon size={18} style={{ color: "var(--accent)" }} aria-hidden />
                  <span>{s.name}</span>
                </h3>
                <span className="brand-badge" style={{ fontSize: "0.72rem" }}>
                  {s.boundary}
                </span>
              </div>
              <p className="muted" style={{ fontSize: "0.88rem", margin: "6px 0 12px" }}>
                {s.description}
              </p>
              <dl>
                <dt style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <Eye size={13} style={{ color: "var(--warn)" }} aria-hidden />
                  <span>Can see:</span>
                </dt>
                <dd style={{ fontWeight: 500 }}>{s.sees}</dd>

                <dt style={{ display: "flex", alignItems: "center", gap: 4 }}>
                  <EyeOff size={13} style={{ color: "var(--ok)" }} aria-hidden />
                  <span>Cannot see:</span>
                </dt>
                <dd style={{ fontWeight: 500, color: "var(--ok)" }}>{s.cannotSee}</dd>
              </dl>
            </div>
            {idx < STAGES.length - 1 && (
              <div className="tb-arrow" aria-hidden>
                <ArrowDown size={18} />
              </div>
            )}
          </div>
        );
      })}
    </section>
  );
}
