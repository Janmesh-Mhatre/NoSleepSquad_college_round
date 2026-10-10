import { useEffect, useState } from "react";
import { PageHeader, StatusBadge, LoadingState, ErrorState, MetricCard } from "../../components/ui";
import { moderationService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { ModerationPolicyConfig } from "../../api/types";
import { SlidersHorizontal, Shield, Cpu, Layers } from "lucide-react";

export function ModerationPolicies() {
  const [config, setConfig] = useState<ModerationPolicyConfig | null>(null);
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");

  useEffect(() => {
    moderationService
      .getPolicies()
      .then(setConfig)
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load moderation policies.");
      })
      .finally(() => setBusy(false));
  }, []);

  if (busy) return <LoadingState message="Loading active moderation policies..." />;
  if (err) return <ErrorState message={err} />;
  if (!config) return null;

  return (
    <>
      <PageHeader
        title="AI Moderation & Rule Configuration"
        lead={`Policy Version: ${config.policyVersion} · Active rule engines and evaluation metrics`}
      />

      <div className="metrics-grid">
        <MetricCard label="Rule Engine Status" value={config.ruleEngineStatus.toUpperCase()} subtext="Automated pre-triage filter" />
        <MetricCard label="False Positive Rate" value={config.metrics.falsePositiveRate} subtext="Monitored over last 90 days" />
        <MetricCard label="False Negative Rate" value={config.metrics.falseNegativeRate} subtext="Critical signal misses" />
        <MetricCard label="Human Overrides" value={config.metrics.humanOverridesCount} subtext="Decisions updated by staff" />
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 16, marginBottom: 24 }}>
        <div className="card">
          <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: 8 }}>
            <Cpu size={16} style={{ color: "var(--accent)" }} aria-hidden />
            <span>NLP Classifier Parameters</span>
          </h3>
          <dl className="tb-node" style={{ border: "none", padding: 0 }}>
            <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: 8, fontSize: "0.88rem" }}>
              <dt className="muted">Model Architecture:</dt>
              <dd className="mono">{config.nlpClassifier.model}</dd>
              <dt className="muted">Model Version:</dt>
              <dd className="mono">{config.nlpClassifier.version}</dd>
              <dt className="muted">Decision Threshold:</dt>
              <dd className="mono">{config.nlpClassifier.threshold}</dd>
              <dt className="muted">Engine State:</dt>
              <dd><StatusBadge kind="ok">{config.nlpClassifier.status}</StatusBadge></dd>
            </div>
          </dl>
        </div>

        <div className="card">
          <h3 style={{ marginTop: 0, display: "flex", alignItems: "center", gap: 8 }}>
            <Shield size={16} style={{ color: "var(--ok)" }} aria-hidden />
            <span>Privacy-Preserving Review Fallback</span>
          </h3>
          <dl className="tb-node" style={{ border: "none", padding: 0 }}>
            <div style={{ display: "grid", gridTemplateColumns: "140px 1fr", gap: 8, fontSize: "0.88rem" }}>
              <dt className="muted">Inference Provider:</dt>
              <dd>{config.optionalLlmReview.provider}</dd>
              <dt className="muted">Privacy Policy:</dt>
              <dd>{config.optionalLlmReview.policy}</dd>
              <dt className="muted">Execution Timeout:</dt>
              <dd className="mono">{config.optionalLlmReview.timeoutMs}ms</dd>
              <dt className="muted">Status:</dt>
              <dd><StatusBadge kind="warn">{config.optionalLlmReview.status}</StatusBadge></dd>
            </div>
          </dl>
        </div>
      </div>

      <div className="card">
        <h3 style={{ marginTop: 0, marginBottom: 16 }}>Active Safety & Triage Rule Set</h3>
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Rule ID</th>
                <th>Rule Name</th>
                <th>Domain Category</th>
                <th>Triage Action</th>
                <th>Specification</th>
              </tr>
            </thead>
            <tbody>
              {config.activeRules.map((rule) => (
                <tr key={rule.id}>
                  <td className="mono">{rule.id}</td>
                  <td style={{ fontWeight: 600 }}>{rule.name}</td>
                  <td>{rule.category}</td>
                  <td>
                    <StatusBadge kind={rule.action === "escalate" ? "danger" : "warn"}>
                      {rule.action}
                    </StatusBadge>
                  </td>
                  <td className="muted" style={{ fontSize: "0.85rem" }}>
                    {rule.description}
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
