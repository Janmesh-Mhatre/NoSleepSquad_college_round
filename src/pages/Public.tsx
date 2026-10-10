import { Link } from "react-router-dom";
import { PageHeader, StatusBadge, PrivacyNotice } from "../components/ui";
import { TrustBoundaryDiagram } from "../components/TrustBoundaryDiagram";
import { Shield, Lock, Layers, EyeOff, AlertTriangle, ArrowRight, CheckCircle2 } from "lucide-react";

export function Landing() {
  return (
    <>
      <section style={{ maxWidth: 840, marginBottom: 36 }}>
        <h1 style={{ fontSize: "2.35rem", lineHeight: 1.15, marginBottom: 16 }}>
          Report institutional concerns without routinely revealing your identity.
        </h1>
        <p className="muted" style={{ fontSize: "1.1rem", lineHeight: 1.6, maxWidth: 740, marginBottom: 24 }}>
          Incognito separates membership verification from report submission. Eligible members can obtain a privacy-preserving credential and submit reports without sending their institutional identity to the reporting service.
        </p>
        <div className="row" style={{ gap: 12 }}>
          <Link className="btn primary" to="/report" style={{ padding: "0 20px", minHeight: 44, fontSize: "0.98rem" }}>
            Submit a Report Securely <ArrowRight size={16} aria-hidden />
          </Link>
          <Link className="btn" to="/how-it-works" style={{ padding: "0 18px", minHeight: 44 }}>
            How Privacy Works
          </Link>
          <Link className="btn" to="/enroll" style={{ padding: "0 18px", minHeight: 44 }}>
            Verify Eligibility
          </Link>
        </div>
      </section>

      <div className="row" style={{ margin: "24px 0 36px", gap: 8 }}>
        {[
          "Anonymous submission",
          "Eligibility verification",
          "Encrypted report storage",
          "AI-assisted moderation",
          "Tamper-evident audit records",
        ].map((t) => (
          <StatusBadge key={t} kind="neutral">
            {t}
          </StatusBadge>
        ))}
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))", gap: 16, marginBottom: 40 }}>
        <div className="card">
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <Lock size={18} style={{ color: "var(--accent)" }} aria-hidden />
            <h3 style={{ margin: 0 }}>Identity Separation</h3>
          </div>
          <p className="muted" style={{ fontSize: "0.9rem" }}>
            Your student ID or institutional account proves your active status, but is never bundled or transmitted with your report payload.
          </p>
        </div>
        <div className="card">
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <EyeOff size={18} style={{ color: "var(--ok)" }} aria-hidden />
            <h3 style={{ margin: 0 }}>End-to-End Encryption</h3>
          </div>
          <p className="muted" style={{ fontSize: "0.9rem" }}>
            Reports are encrypted with authenticated AES-256-GCM before storage. Only designated institutional reviewers hold role keys.
          </p>
        </div>
        <div className="card">
          <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 8 }}>
            <Layers size={18} style={{ color: "var(--warn)" }} aria-hidden />
            <h3 style={{ margin: 0 }}>Tamper-Evident Audits</h3>
          </div>
          <p className="muted" style={{ fontSize: "0.9rem" }}>
            Audit records are batched into cryptographic Merkle trees and anchored to public testnets, guaranteeing report inclusion without exposing content.
          </p>
        </div>
      </div>

      <div style={{ marginTop: 24 }}>
        <h2 style={{ marginBottom: 12 }}>System Architecture & Trust Boundaries</h2>
        <p className="muted" style={{ marginBottom: 20 }}>
          Examine the distinct trust boundaries enforced between identity providers, report gateways, and storage nodes.
        </p>
        <TrustBoundaryDiagram />
      </div>

      <div style={{ marginTop: 32 }}>
        <PrivacyNotice title="Explicit Technical Limitations Notice">
          <p style={{ margin: 0, fontSize: "0.9rem" }}>
            <strong>Incognito does not claim 100% untraceability.</strong> No automated cryptographic system can protect against compromised user endpoints, device surveillance, or identifying details voluntarily written inside the report text itself. Learn more in our <Link to="/security">threat model and limitations disclosure</Link>.
          </p>
        </PrivacyNotice>
      </div>
    </>
  );
}

export function HowItWorks() {
  return (
    <>
      <PageHeader
        title="How Incognito Works"
        lead="A protocol-level walkthrough of identity separation, anonymous verification, and encrypted storage."
      />

      <section className="card" style={{ marginBottom: 24 }}>
        <h2 style={{ marginTop: 0 }}>The Separation Architecture</h2>
        <p>
          Traditional institutional reporting systems link every submitted concern to the reporter's user account, email address, and IP logging records. Even when labeled "anonymous," standard databases still maintain foreign key linkages or network access logs.
        </p>
        <p>
          Incognito eliminates this architectural link by dividing the process into two distinct domains:
        </p>
        <ol style={{ paddingLeft: 20, margin: "16px 0", lineHeight: 1.7 }}>
          <li>
            <strong>The Verification Domain:</strong> Uses your institutional account to verify that you are an active student, researcher, or staff member. The issuer registers a cryptographic commitment and hands your client an unlinked credential.
          </li>
          <li>
            <strong>The Reporting Domain:</strong> Accepts report text accompanied solely by an anonymous cryptographic proof. It possesses zero access to your institutional account, student ID, or personal record.
          </li>
        </ol>
      </section>

      <h2 style={{ marginBottom: 12 }}>Interactive Trust Boundary Inspection</h2>
      <TrustBoundaryDiagram />

      <section className="card" style={{ marginTop: 28 }}>
        <h2 style={{ marginTop: 0 }}>Metadata Minimization & Operational Hygiene</h2>
        <p className="muted">
          Our gateway enforces strict HTTP transport hygiene:
        </p>
        <ul style={{ paddingLeft: 20, margin: "12px 0", lineHeight: 1.7, fontSize: "0.92rem" }}>
          <li>HTTP response headers mandate <code>Cache-Control: no-store</code>, preventing draft persistence in intermediate proxies.</li>
          <li>Server frameworks strip <code>X-Powered-By</code> and client IP logging from the reporting database.</li>
          <li>Status secrets are stored exclusively as one-way SHA-256 hashes and cannot be derived from the public reference.</li>
          <li>Topic-scoped nullifiers prevent spam repeat submissions while preserving unlinkability across categories.</li>
        </ul>
      </section>
    </>
  );
}

export function Security() {
  return (
    <>
      <PageHeader
        title="Security Architecture & Threat Model"
        lead="A transparent breakdown of technical defenses, cryptographic mechanisms, and operational limitations."
      />

      <div style={{ display: "grid", gap: 20 }}>
        <section className="card">
          <h2 style={{ marginTop: 0 }}>1. Identity Separation</h2>
          <p>
            Institutional Single Sign-On (SSO) and report ingestion operate on completely separate infrastructure. The reporting database contains zero foreign keys, student IDs, or email associations. The reporting backend accepts requests with anonymous cryptographic credentials.
          </p>
        </section>

        <section className="card">
          <h2 style={{ marginTop: 0 }}>2. Topic-Scoped Duplicate Prevention</h2>
          <p>
            To prevent coordinated denial-of-service or repeat spam submissions without tracking individual users, Incognito employs deterministic scope-bound nullifier digests. A user cannot submit duplicate reports within the same incident scope, yet nullifiers cannot be correlated across different categories or topics.
          </p>
        </section>

        <section className="card">
          <h2 style={{ marginTop: 0 }}>3. Encrypted Report Storage</h2>
          <p>
            All submitted reports are encrypted using authenticated symmetric encryption (AES-256-GCM) prior to insertion into SQLite persistent storage. Moderation tags and priority scores are computed during submission and stored alongside the encrypted payload.
          </p>
        </section>

        <section className="card">
          <h2 style={{ marginTop: 0 }}>4. Blockchain Auditing Guarantees</h2>
          <p>
            Off-chain audit events are periodically batched into deterministic SHA-256 Merkle trees. The 32-byte Merkle root is committed to an Ethereum-compatible AuditRegistry smart contract. This provides tamper-evident mathematical proof that a report was accepted and unmodified, without exposing report contents to the public ledger.
          </p>
        </section>

        <section className="card" style={{ borderLeft: "4px solid var(--warn)" }}>
          <h2 style={{ marginTop: 0 }}>5. Threat Model: Assumed Adversaries</h2>
          <div style={{ display: "grid", gap: 12, marginTop: 12 }}>
            <div>
              <strong>Malicious Administrator:</strong> May attempt to correlate reporting timestamps with campus network activity. Mitigated by metadata minimization, unlinked submissions, and randomized reference generation.
            </div>
            <div>
              <strong>Compromised Backend:</strong> Even with full database read access, the adversary observes only encrypted bodies, random references, and SHA-256 hashed secrets.
            </div>
            <div>
              <strong>Malicious Credential Issuer:</strong> The issuer knows only that a member verified eligibility; it never receives report content or notification of when a report is submitted.
            </div>
            <div>
              <strong>Traffic Analysis:</strong> Sophisticated network adversaries monitoring institutional Wi-Fi may observe TLS connections to the gateway. Users addressing critical safety concerns are encouraged to use Tor or private networks.
            </div>
          </div>
        </section>

        <section className="card" style={{ borderLeft: "4px solid var(--danger)" }}>
          <h2 style={{ marginTop: 0 }}>6. Technical Limitations & Non-Claims</h2>
          <ul style={{ paddingLeft: 20, margin: "12px 0", lineHeight: 1.7 }}>
            <li><strong>Endpoint Compromise:</strong> If your local computer has keyloggers, screen recording software, or institutional device management installed, your report text may be captured at input time.</li>
            <li><strong>Stylometry & Content Leaks:</strong> If you include unique personal details, specific room numbers known only to you, or highly distinctive phrasing, readers may infer your identity regardless of cryptographic protections.</li>
            <li><strong>Blockchain Ground Truth:</strong> An on-chain Merkle commitment proves that an audit record was timestamped and retained; it cannot prove whether the underlying human statement is factually accurate.</li>
          </ul>
        </section>
      </div>
    </>
  );
}

const FAQ_ITEMS = [
  {
    q: "Who can submit a report?",
    a: "Any active student, staff member, or institutional affiliate who completes the eligibility check can acquire a credential and submit a report.",
  },
  {
    q: "Does Incognito know who I am?",
    a: "The reporting gateway does not receive your student ID, name, email, or institutional account. It receives only your chosen category, concern text, and a cryptographic proof.",
  },
  {
    q: "Does the college receive my identity?",
    a: "The college identity provider verifies only that you are an eligible affiliate. The report submission itself is sent to the reporting service without your identity attached.",
  },
  {
    q: "Can administrators see who submitted a report?",
    a: "No. The administrative and moderator consoles display only anonymous references (e.g. INC-849204), categories, moderation scores, and encrypted texts. No identity fields exist in the database.",
  },
  {
    q: "Can I submit multiple reports?",
    a: "You may submit reports for different topics. To prevent denial-of-service and flooding, a topic-scoped nullifier prevents submitting identical duplicate reports within the same incident scope.",
  },
  {
    q: "What information is stored?",
    a: "The system stores the chosen category, AES-256-GCM encrypted report text, random reference, SHA-256 hash of your status secret, automated priority score, and timestamp.",
  },
  {
    q: "Does the blockchain store my report?",
    a: "No. The blockchain stores only 32-byte cryptographic Merkle roots of batched audit hashes. Plaintext report content and personal details are never sent to the blockchain.",
  },
  {
    q: "Can my report be deleted?",
    a: "Moderators can close cases and update case statuses, but audit records committed to on-chain Merkle batches provide tamper-evident proof that the submission was recorded.",
  },
  {
    q: "What happens after submission?",
    a: "Your report is evaluated by automated rule filters, assigned an initial priority, and queued in the moderator review console. You receive a reference and status access secret to track its progress.",
  },
  {
    q: "What happens if moderation flags my report?",
    a: "Flagged reports are automatically elevated for immediate moderator review, particularly if hazardous physical conditions or threats of retaliation are detected.",
  },
  {
    q: "What happens if the blockchain is unavailable?",
    a: "Your report is accepted and stored normally. Audit records remain queued in the off-chain SQLite database and are published once connectivity to the smart contract is restored.",
  },
  {
    q: "What are the limitations of anonymity?",
    a: "Incognito protects your digital transmission and storage. However, if you submit from a monitored institutional computer, or write details that only you could know, you may inadvertently reveal your identity.",
  },
];

export function Help() {
  return (
    <>
      <PageHeader
        title="Frequently Asked Questions"
        lead="Clear, technically accurate answers derived directly from our architecture and backend implementation."
      />

      <div className="card">
        {FAQ_ITEMS.map((item) => (
          <details key={item.q}>
            <summary>{item.q}</summary>
            <p>{item.a}</p>
          </details>
        ))}
      </div>

      <div style={{ marginTop: 24 }}>
        <p className="muted" style={{ fontSize: "0.9rem" }}>
          Need assistance with a critical situation? Contact your campus ombudsperson or emergency services directly if you face imminent physical danger.
        </p>
      </div>
    </>
  );
}

export function Privacy() {
  return (
    <>
      <PageHeader
        title="Institutional Privacy Policy"
        lead="Our formal data governance, metadata minimization, and cryptographic handling commitments."
      />

      <div className="card" style={{ display: "grid", gap: 16 }}>
        <div>
          <h3>1. Identity Decoupling Principle</h3>
          <p className="muted">
            The Incognito platform is engineered around complete identity decoupling. Institutional authentication tokens are validated exclusively at the verification gateway and are never passed to the reporting gateway or persisted in reporting storage.
          </p>
        </div>

        <div>
          <h3>2. Zero Personal Data Storage</h3>
          <p className="muted">
            The reporting database schema contains no columns for student IDs, staff numbers, names, email addresses, phone numbers, or hardware identifiers. All submission identifiers are randomly generated integers prefixed with <code>INC-</code>.
          </p>
        </div>

        <div>
          <h3>3. In-Memory Draft Policy</h3>
          <p className="muted">
            Draft reports are kept exclusively in component memory. We do not persist report drafts in browser <code>localStorage</code>, <code>sessionStorage</code>, or IndexedDB. When you close or refresh the tab, any unsubmitted draft text is cleared immediately.
          </p>
        </div>

        <div>
          <h3>4. Access Secrets & Lookup Isolation</h3>
          <p className="muted">
            Status lookup requires both the random reference and a dedicated high-entropy status secret. Secrets are hashed with SHA-256 upon generation. Staff members and administrators cannot access report tracking on behalf of an anonymous reporter without this secret.
          </p>
        </div>

        <div>
          <h3>5. Retention & Audit Logs</h3>
          <p className="muted">
            Closed reports are retained in encrypted form per institutional governance requirements. Public blockchain commitments contain only one-way Merkle roots and do not contain readable text or individual submission identities.
          </p>
        </div>
      </div>
    </>
  );
}
