import { Router } from "express";
import { reportService, ReportError } from "../services/reportService.js";

export const reportsRouter = Router();

// GET /api/reports/categories
reportsRouter.get("/reports/categories", (_req, res) => {
  const categories = reportService.getCategories();
  res.json(categories);
});

// POST /api/reports
reportsRouter.post("/reports", async (req, res, next) => {
  try {
    const { categoryId, body, proofNullifier, proof } = req.body || {};
    const idempotencyKey = (req.headers["idempotency-key"] as string) || undefined;

    const result = await reportService.submitReport({
      categoryId,
      body,
      idempotencyKey,
      proofNullifier,
      proof,
    });

    res.status(201).json(result);
  } catch (err) {
    if (err instanceof ReportError) {
      return res.status(err.status).json({ code: err.code, message: err.message });
    }
    next(err);
  }
});

// GET /api/reports/:id/identity -> Explicitly prohibited
reportsRouter.all("/reports/:id/identity", (_req, res) => {
  res.status(403).json({
    error: "forbidden_operation",
    message: "Identity lookup is cryptographically and architecturally prohibited in Incognito. Reports have no identity association.",
  });
});

// POST /api/reports/status
reportsRouter.post("/reports/status", (req, res, next) => {
  try {
    const { reference, statusSecret } = req.body || {};
    if (!reference || !statusSecret) {
      return res.status(400).json({ code: "invalid_request", message: "Reference and statusSecret are required." });
    }

    const result = reportService.getReportStatus(reference, statusSecret);
    res.json(result);
  } catch (err) {
    if (err instanceof ReportError) {
      return res.status(err.status).json({ code: err.code, message: err.message });
    }
    next(err);
  }
});
