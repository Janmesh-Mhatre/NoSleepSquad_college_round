import { Router, type Request } from "express";
import { membershipService } from "../services/membershipService.js";
import { authService } from "../services/authService.js";
import { oidcService } from "../services/oidcService.js";
import { env } from "../config/env.js";

export const credentialRouter = Router();

async function resolveMemberRef(req: Request): Promise<string | null> {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.substring(7).trim();
    if (token) {
      try {
        const claims = authService.verifyToken(token);
        return claims.sub;
      } catch {
        // Not internal token, try OIDC
      }

      try {
        const oidcResult = await oidcService.verifyInstitutionalToken(token);
        if (oidcResult.eligible) {
          return oidcResult.eligibilityProofHash;
        }
      } catch {
        // Invalid OIDC
      }
    }
    return null;
  }

  // Deployed environments fail closed
  const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
  if (isDeployed) {
    return null;
  }

  // Development shortcuts require explicit configuration
  const currentEnv = (process.env.NODE_ENV || "development").toLowerCase();
  const isDev = currentEnv === "development" || currentEnv === "test";
  const devAuthAllowed = isDev && (process.env.ALLOW_DEV_AUTH === "true" || process.env.DEV_AUTH_ENABLED === "true");

  if (devAuthAllowed) {
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
credentialRouter.get("/credential/status", async (req, res) => {
  const memberRef = await resolveMemberRef(req);
  if (!memberRef) {
    return res.status(401).json({ error: "unauthenticated", message: "Authentication required to query credential status." });
  }
  const status = membershipService.getStatus(memberRef);
  
  return res.json({
    state: status.credentialStatus === "registered" ? "active" : status.credentialStatus,
    expiresAt: status.expiresAt,
    registered: status.credentialRegistered,
    anonymousVerificationReady: status.anonymousVerificationReady,
  });
});
