import { Router } from "express";
import { securityService } from "../services/securityService.js";

export const securityRouter = Router();

// GET /api/security/tests
securityRouter.get("/security/tests", (_req, res) => {
  res.json(securityService.runSecurityAudit());
});

// POST /api/security/tests/run
securityRouter.post("/security/tests/run", (_req, res) => {
  res.json(securityService.runSecurityAudit());
});
