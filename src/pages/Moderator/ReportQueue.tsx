import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { PageHeader, StatusBadge, LoadingState, ErrorState, EmptyState } from "../../components/ui";
import { reportService } from "../../api/services";
import { ApiError } from "../../api/client";
import type { ModeratorReportSummary, ReportCategory } from "../../api/types";
import { Search, Filter, RefreshCw, Eye } from "lucide-react";

export function ReportQueue() {
  const [reports, setReports] = useState<ModeratorReportSummary[]>([]);
  const [categories, setCategories] = useState<ReportCategory[]>([]);
  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [priorityFilter, setPriorityFilter] = useState("all");
  const [busy, setBusy] = useState(true);
  const [err, setErr] = useState("");

  function loadQueue() {
    setBusy(true);
    setErr("");
    Promise.all([
      reportService.getModeratorReports({
        status: statusFilter,
        categoryId: categoryFilter,
        priority: priorityFilter,
        search: search.trim() || undefined,
      }),
      reportService.getCategories(),
    ])
      .then(([reps, cats]) => {
        setReports(reps);
        setCategories(cats);
      })
      .catch((e) => {
        setErr(e instanceof ApiError ? e.message : "Failed to load reports queue.");
      })
      .finally(() => setBusy(false));
  }

  useEffect(() => {
    loadQueue();
  }, [statusFilter, categoryFilter, priorityFilter]);

  function handleSearchSubmit(e: React.FormEvent) {
    e.preventDefault();
    loadQueue();
  }

  return (
    <>
      <PageHeader
        title="Anonymous Report Queue"
        lead="Manage incoming institutional submissions. Identifying data is stripped at the gateway."
        actions={
          <button type="button" className="btn sm" onClick={loadQueue} disabled={busy}>
            <RefreshCw size={13} aria-hidden /> Refresh Queue
          </button>
        }
      />

      <div className="card" style={{ padding: 14, marginBottom: 16 }}>
        <form onSubmit={handleSearchSubmit} className="row" style={{ gap: 12 }}>
          <div style={{ flex: 1, minWidth: 200, position: "relative" }}>
            <input
              placeholder="Search reference (e.g. INC-849204)..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="mono"
              style={{ paddingLeft: 32 }}
            />
            <Search size={14} style={{ position: "absolute", left: 10, top: 12, color: "var(--text-dim)" }} aria-hidden />
          </div>

          <div style={{ minWidth: 140 }}>
            <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
              <option value="all">All Statuses</option>
              <option value="received">Received</option>
              <option value="under_review">Under Review</option>
              <option value="moderation_review">Moderation Review</option>
              <option value="assigned">Assigned</option>
              <option value="action_taken">Action Taken</option>
              <option value="closed">Closed</option>
            </select>
          </div>

          <div style={{ minWidth: 150 }}>
            <select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)}>
              <option value="all">All Categories</option>
              {categories.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.name}
                </option>
              ))}
            </select>
          </div>

          <div style={{ minWidth: 120 }}>
            <select value={priorityFilter} onChange={(e) => setPriorityFilter(e.target.value)}>
              <option value="all">All Priorities</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </select>
          </div>

          <button type="submit" className="btn primary sm" disabled={busy}>
            Filter
          </button>
        </form>
      </div>

      {busy && <LoadingState message="Querying authorized report queue..." />}
      {err && <ErrorState message={err} onRetry={loadQueue} />}

      {!busy && !err && reports.length === 0 ? (
        <EmptyState title="No reports found in queue">
          No reports match the current query filter. Try clearing filters or resetting the search term.
        </EmptyState>
      ) : (
        <div className="table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>Reference</th>
                <th>Category</th>
                <th>Status</th>
                <th>Priority</th>
                <th>Safety Signals</th>
                <th>Moderation Conf.</th>
                <th>Received</th>
                <th>Moderator</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {reports.map((r) => (
                <tr key={r.id}>
                  <td className="mono" style={{ fontWeight: 600 }}>{r.reference}</td>
                  <td>{r.categoryName}</td>
                  <td>
                    <StatusBadge kind={r.status === "received" ? "warn" : r.status === "closed" ? "neutral" : "ok"}>
                      {r.status.replace(/_/g, " ")}
                    </StatusBadge>
                  </td>
                  <td>
                    <span className={`badge ${r.priority === "high" || r.priority === "critical" ? "danger" : r.priority === "medium" ? "warn" : "neutral"}`}>
                      {r.priority}
                    </span>
                  </td>
                  <td>
                    <span className="muted" style={{ fontSize: "0.82rem" }}>
                      {r.moderationResult.detectedSignals.slice(0, 2).join(", ")}
                    </span>
                  </td>
                  <td>
                    <span className="mono" style={{ fontSize: "0.82rem" }}>
                      {Math.round(r.moderationResult.confidence * 100)}%
                    </span>
                  </td>
                  <td className="muted" style={{ fontSize: "0.82rem" }}>
                    {new Date(r.createdAt).toLocaleDateString()}
                  </td>
                  <td className="muted" style={{ fontSize: "0.82rem" }}>
                    {r.assignedModerator || "—"}
                  </td>
                  <td>
                    <Link to={`/moderator/reports/${r.id}`} className="btn sm">
                      <Eye size={13} aria-hidden /> Review
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </>
  );
}
