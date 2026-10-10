import { Router } from "express";
import { membershipService } from "../services/membershipService.js";

export const credentialRouter = Router();

// GET /api/credential/status
// Returns the status of the caller's credential
credentialRouter.get("/credential/status", (req, res) => {
  const memberRef = (req.query.ref as string) || (req.headers["x-member-ref"] as string) || "demo-member-01";
  const status = membershipService.getStatus(memberRef);
  
  res.json({
    state: status.credentialStatus === "registered" ? "active" : status.credentialStatus,
    expiresAt: status.expiresAt,
    registered: status.credentialRegistered,
    anonymousVerificationReady: status.anonymousVerificationReady,
  });
});
