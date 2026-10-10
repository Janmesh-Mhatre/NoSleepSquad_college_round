import { Router } from "express";
import { auditService } from "../services/auditService.js";

export const auditRouter = Router();

// GET /api/audit/batches
auditRouter.get("/audit/batches", (_req, res) => {
  res.json(auditService.getBatches());
});

// GET /api/audit/batches/:id/records
auditRouter.get("/audit/batches/:id/records", (req, res) => {
  res.json(auditService.getBatchRecords(req.params.id));
});

// POST /api/audit/verify/:batchId
auditRouter.post("/audit/verify/:batchId", (req, res) => {
  try {
    const result = auditService.verifyBatch(req.params.batchId);
    res.json(result);
  } catch (err) {
    res.status(400).json({ error: (err as Error).message });
  }
});

// GET /api/audit/status
auditRouter.get("/audit/status", (_req, res) => {
  res.json(auditService.getQueueStatus());
});
