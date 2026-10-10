import { ReactNode } from "react";
import { CheckCircle, Clock, AlertTriangle, XCircle, Circle, ShieldCheck, Loader2 } from "lucide-react";

const MAP = {
  ok: CheckCircle,
  pending: Clock,
  warn: AlertTriangle,
  danger: XCircle,
  neutral: Circle,
  verified: ShieldCheck,
} as const;

export function StatusBadge({
  kind,
  children,
}: {
  kind: keyof typeof MAP;
  children: ReactNode;
}) {
  const Icon = MAP[kind];
  const cssClass = kind === "pending" ? "warn" : kind === "verified" ? "ok" : kind;
  return (
    <span className={`badge ${cssClass}`}>
      <Icon size={13} aria-hidden />
      <span>{children}</span>
    </span>
  );
}

export function PageHeader({
  title,
  lead,
  actions,
}: {
  title: string;
  lead?: string;
  actions?: ReactNode;
}) {
  return (
    <header style={{ marginBottom: 24, display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
      <div>
        <h1 style={{ marginBottom: lead ? 6 : 0 }}>{title}</h1>
        {lead && <p className="muted" style={{ margin: 0, maxWidth: 720 }}>{lead}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </header>
  );
}

export function EmptyState({
  title,
  children,
  action,
}: {
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty" role="status">
      <strong>{title}</strong>
      {children && <p style={{ maxWidth: 540, margin: "8px auto 0" }}>{children}</p>}
      {action && <div style={{ marginTop: 16 }}>{action}</div>}
    </div>
  );
}

export function ErrorState({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="err" role="alert" style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
        <AlertTriangle size={15} aria-hidden />
        <span>{message}</span>
      </div>
      {onRetry && (
        <button type="button" className="btn sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}

export function LoadingState({ message = "Loading securely..." }: { message?: string }) {
  return (
    <div className="loading-box" role="status">
      <Loader2 size={18} className="spin" aria-hidden style={{ animation: "spin 1s linear infinite" }} />
      <span>{message}</span>
      <style>{`@keyframes spin { 100% { transform: rotate(360deg); } }`}</style>
    </div>
  );
}

export function StepIndicator({
  steps,
  current,
}: {
  steps: string[];
  current: number;
}) {
  return (
    <ol className="steps" aria-label="Progress">
      {steps.map((s, i) => (
        <li
          key={s}
          aria-current={i === current ? "step" : undefined}
          style={{ opacity: i > current ? 0.6 : 1 }}
        >
          <span className="mono" style={{ fontSize: "0.8rem", color: i === current ? "var(--accent)" : "var(--text-dim)" }}>
            {String(i + 1).padStart(2, "0")}
          </span>
          <span>{s}</span>
        </li>
      ))}
    </ol>
  );
}

export function PrivacyNotice({
  children,
  title = "Privacy Architecture Notice",
}: {
  children: ReactNode;
  title?: string;
}) {
  return (
    <aside className="card" aria-label={title} style={{ borderLeft: "4px solid var(--accent)", background: "var(--surface-secondary)" }}>
      <h3 style={{ fontSize: "0.95rem", textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--text-dim)", marginBottom: 8 }}>
        {title}
      </h3>
      <div>{children}</div>
    </aside>
  );
}

export function MetricCard({
  label,
  value,
  subtext,
}: {
  label: string;
  value: string | number;
  subtext?: string;
}) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      {subtext && <div className="muted" style={{ fontSize: "0.8rem", marginTop: 4 }}>{subtext}</div>}
    </div>
  );
}

export function ConfirmationModal({
  isOpen,
  title,
  children,
  onConfirm,
  onCancel,
  confirmLabel = "Confirm",
  confirmDanger = false,
  busy = false,
}: {
  isOpen: boolean;
  title: string;
  children: ReactNode;
  onConfirm: () => void;
  onCancel: () => void;
  confirmLabel?: string;
  confirmDanger?: boolean;
  busy?: boolean;
}) {
  if (!isOpen) return null;

  return (
    <div
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      style={{
        position: "fixed",
        inset: 0,
        backgroundColor: "rgba(10, 12, 16, 0.6)",
        backdropFilter: "blur(2px)",
        display: "flex",
        alignItems: "center",
        justifyContent: "center",
        zIndex: 1000,
        padding: 16,
      }}
      onClick={(e) => {
        if (e.target === e.currentTarget) onCancel();
      }}
    >
      <div
        className="card"
        style={{
          width: "100%",
          maxWidth: 480,
          background: "var(--surface)",
          boxShadow: "var(--shadow-md)",
        }}
      >
        <h2 id="modal-title" style={{ marginTop: 0, fontSize: "1.2rem" }}>
          {title}
        </h2>
        <div style={{ margin: "16px 0" }}>{children}</div>
        <div className="row" style={{ justifyContent: "flex-end", gap: 8 }}>
          <button type="button" className="btn" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className={`btn ${confirmDanger ? "danger" : "primary"}`}
            onClick={onConfirm}
            disabled={busy}
          >
            {busy ? "Processing..." : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
