import { Router, type Request } from "express";
import { membershipService, MembershipError } from "../services/membershipService.js";
import { authService, AuthError } from "../services/authService.js";
import { oidcService } from "../services/oidcService.js";
import { isValidSemaphoreCommitment } from "../services/credentialService.js";
import { env } from "../config/env.js";

export const membershipRouter = Router();

/**
 * Resolves the authenticated institutional member identity.
 *
 * Security Invariants:
 * 1. Cryptographic token verification is required (Bearer JWT or institutional OIDC ID token).
 * 2. Caller-controlled identifiers (body.memberRef, query.ref, x-member-ref) are STRICTLY REJECTED
 *    in all deployed environments (staging and production).
 * 3. Fallbacks to 'demo-member-01' are prohibited outside explicit development mode with ALLOW_DEV_AUTH=true.
 */
async function resolveMemberRef(req: Request): Promise<string | null> {
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith("Bearer ")) {
    const token = authHeader.substring(7).trim();
    if (token) {
      // 1. Check internal authenticated session JWT
      try {
        const claims = authService.verifyToken(token);
        return claims.sub;
      } catch {
        // Not an internal JWT, attempt OIDC verification
      }

      // 2. Check institutional OIDC ID token
      try {
        const oidcResult = await oidcService.verifyInstitutionalToken(token);
        if (oidcResult.eligible) {
          return oidcResult.eligibilityProofHash;
        }
      } catch {
        // Invalid OIDC token
      }
    }
    return null;
  }

  // Check if idToken was passed directly in request body
  if (req.body?.idToken && typeof req.body.idToken === "string" && req.body.idToken.trim()) {
    try {
      const oidcResult = await oidcService.verifyInstitutionalToken(req.body.idToken.trim());
      if (oidcResult.eligible) {
        return oidcResult.eligibilityProofHash;
      }
    } catch {
      return null;
    }
  }

  // In deployed environments (staging / production), fail closed immediately
  const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
  if (isDeployed) {
    return null;
  }

  // In local development, shortcuts are ONLY allowed if explicitly enabled by developer configuration
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

membershipRouter.get("/membership/status", async (req, res) => {
  const memberRef = await resolveMemberRef(req);
  if (!memberRef) {
    return res.status(401).json({
      error: "unauthenticated",
      message: "Valid institutional authentication token required to query membership status.",
    });
  }
  const status = membershipService.getStatus(memberRef);
  return res.json(status);
});

membershipRouter.post("/membership/enroll", async (req, res, next) => {
  try {
    const memberRef = await resolveMemberRef(req);
    if (!memberRef) {
      return res.status(401).json({
        error: "unauthenticated",
        message: "Valid institutional authentication token or OIDC ID token required for enrollment.",
      });
    }
    const clientCommitment = req.body?.commitment;
    if (!clientCommitment || typeof clientCommitment !== "string" || !isValidSemaphoreCommitment(clientCommitment)) {
      return res.status(400).json({
        error: "invalid_commitment",
        message: "A valid client-owned Semaphore identity commitment is required.",
      });
    }
    const result = membershipService.enroll(memberRef, clientCommitment);
    return res.status(201).json(result);
  } catch (err) {
    if (err instanceof MembershipError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    next(err);
  }
});

membershipRouter.post("/membership/revoke", (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";

    // In all deployed environments (staging AND production), administrator authorization is strictly required
    if (isDeployed) {
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({
          error: "unauthenticated",
          message: "Administrator authentication required to revoke members.",
        });
      }
      const claims = authService.verifyToken(authHeader.substring(7).trim());
      if (claims.role !== "admin") {
        return res.status(403).json({
          error: "forbidden",
          message: "Only administrators can revoke institutional memberships.",
        });
      }
    } else {
      if (authHeader && authHeader.startsWith("Bearer ")) {
        const claims = authService.verifyToken(authHeader.substring(7).trim());
        if (claims.role !== "admin") {
          return res.status(403).json({
            error: "forbidden",
            message: "Only administrators can revoke institutional memberships.",
          });
        }
      }
    }

    const memberRef = req.body?.memberRef;
    const reason = req.body?.reason;
    if (!memberRef || typeof memberRef !== "string" || !memberRef.trim()) {
      return res.status(400).json({ error: "invalid_request", message: "Member reference is required." });
    }
    const result = membershipService.revoke(memberRef.trim(), reason);
    return res.json(result);
  } catch (err) {
    if (err instanceof MembershipError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    if (err instanceof AuthError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    next(err);
  }
});

membershipRouter.post("/membership/validate", async (req, res) => {
  const memberRef = await resolveMemberRef(req);
  if (!memberRef) {
    return res.status(401).json({
      error: "unauthenticated",
      message: "Valid institutional authentication token required to validate membership.",
    });
  }
  const result = membershipService.validate(memberRef);
  return res.json(result);
});
