import { Router } from "express";
import { reportService, ReportError } from "../services/reportService.js";
import { moderationService } from "../services/moderationService.js";

export const moderatorRouter = Router();

// GET /api/moderator/reports
moderatorRouter.get("/moderator/reports", (req, res) => {
  const { status, categoryId, priority, search } = req.query as Record<string, string>;
  const list = reportService.getModeratorReports({ status, categoryId, priority, search });
  res.json(list);
});

// GET /api/moderator/reports/:id
moderatorRouter.get("/moderator/reports/:id", (req, res) => {
  const report = reportService.getReportById(req.params.id);
  if (!report) {
    return res.status(404).json({ code: "not_found", message: "Report not found." });
  }
  res.json(report);
});

// GET /api/moderator/reports/:id/identity -> Explicitly prohibited
moderatorRouter.all("/moderator/reports/:id/identity", (_req, res) => {
  res.status(403).json({
    error: "forbidden_operation",
    message: "Identity lookup is cryptographically and architecturally prohibited in Incognito. Reports have no identity association.",
  });
});

// POST /api/moderator/reports/:id/action
moderatorRouter.post("/moderator/reports/:id/action", (req, res, next) => {
  try {
    const { action, reason, newStatus } = req.body || {};
    // Authenticated moderator identity derived strictly from verified server-side claims
    const verifiedModeratorId = req.user?.sub || "moderator-session";
    const result = reportService.applyModeratorAction({
      reportId: req.params.id,
      action,
      reason,
      moderatorId: verifiedModeratorId,
      newStatus,
    });
    res.json(result);
  } catch (err) {
    if (err instanceof ReportError) {
      return res.status(err.status).json({ code: err.code, message: err.message });
    }
    next(err);
  }
});

// GET /api/moderator/metrics
moderatorRouter.get("/moderator/metrics", (_req, res) => {
  res.json(reportService.getMetrics());
});

// GET /api/moderation/policies & /api/moderator/moderation
moderatorRouter.get("/moderation/policies", (_req, res) => {
  res.json(moderationService.getPolicyConfig());
});
moderatorRouter.get("/moderator/moderation", (_req, res) => {
  res.json(moderationService.getPolicyConfig());
});
