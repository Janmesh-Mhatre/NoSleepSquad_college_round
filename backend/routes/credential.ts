import { Router, type Request } from "express";
import { membershipService } from "../services/membershipService.js";
import { authService } from "../services/authService.js";
import { env } from "../config/env.js";

export const credentialRouter = Router();

function resolveMemberRef(req: Request): string | null {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    try {
      const claims = authService.verifyToken(authHeader.substring(7).trim());
      return claims.sub;
    } catch {
      return null;
    }
  }

  if (env.nodeEnv !== "production" && process.env.NODE_ENV !== "production") {
    const rawRef = (req.query.ref as string) || (req.body?.memberRef as string) || (req.headers["x-member-ref"] as string);
    if (rawRef && typeof rawRef === "string" && rawRef.trim()) {
      return rawRef.trim();
    }
    return "demo-member-01";
  }

  return null;
}

// GET /api/credential/status
// Returns the status of the caller's credential
credentialRouter.get("/credential/status", (req, res) => {
  const memberRef = resolveMemberRef(req);
  if (!memberRef) {
    return res.status(401).json({ error: "unauthenticated", message: "Authentication required to query credential status." });
  }
  const status = membershipService.getStatus(memberRef);
  
  res.json({
    state: status.credentialStatus === "registered" ? "active" : status.credentialStatus,
    expiresAt: status.expiresAt,
    registered: status.credentialRegistered,
    anonymousVerificationReady: status.anonymousVerificationReady,
  });
});
