import { ArrowRight, FileCheck, Layers, Cpu, Hash, ShieldCheck, CheckCircle2 } from "lucide-react";

const STAGES = [
  {
    title: "1. Accepted Report",
    desc: "Payload encrypted; SHA-256 leaf commitment generated",
    icon: FileCheck,
  },
  {
    title: "2. Audit Queue",
    desc: "Buffered in local SQLite queue awaiting batch threshold",
    icon: Layers,
  },
  {
    title: "3. Merkle Tree",
    desc: "Deterministic SHA-256 binary tree recomputes batch root",
    icon: Cpu,
  },
  {
    title: "4. Root Commitment",
    desc: "32-byte cryptographic root hashed across all leaves",
    icon: Hash,
  },
  {
    title: "5. Smart Contract",
    desc: "Committed to AuditRegistry smart contract",
    icon: ShieldCheck,
  },
  {
    title: "6. Verification",
    desc: "Independent cryptographic proof confirms inclusion",
    icon: CheckCircle2,
  },
];

export function AuditPipelineDiagram() {
  return (
    <div className="card" style={{ padding: 16, marginBottom: 24, overflowX: "auto" }}>
      <h3 style={{ fontSize: "0.92rem", textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--text-dim)", marginBottom: 12 }}>
        Cryptographic Audit Pipeline (Off-chain to On-chain)
      </h3>
      <div className="pipeline-track" style={{ minWidth: 780 }}>
        {STAGES.map((s, idx) => {
          const Icon = s.icon;
          return (
            <div key={s.title} style={{ display: "flex", alignItems: "center", gap: 8, flex: 1 }}>
              <div className="pipeline-step" style={{ flex: 1 }}>
                <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
                  <Icon size={14} style={{ color: "var(--accent)" }} aria-hidden />
                  <span className="pipeline-step-title">{s.title}</span>
                </div>
                <div className="pipeline-step-desc muted" style={{ fontSize: "0.8rem", marginTop: 4 }}>
                  {s.desc}
                </div>
              </div>
              {idx < STAGES.length - 1 && (
                <ArrowRight size={14} style={{ color: "var(--text-dim)", flexShrink: 0 }} aria-hidden />
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
