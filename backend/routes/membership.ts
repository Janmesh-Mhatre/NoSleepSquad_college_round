import { Router, type Request } from "express";
import { membershipService, MembershipError } from "../services/membershipService.js";
import { authService } from "../services/authService.js";
import { env } from "../config/env.js";

export const membershipRouter = Router();

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

  // Development/Test fallback strictly forbidden in production
  if (env.nodeEnv !== "production" && process.env.NODE_ENV !== "production") {
    const rawRef = (req.query.ref as string) || (req.body?.memberRef as string) || (req.headers["x-member-ref"] as string);
    if (rawRef && typeof rawRef === "string" && rawRef.trim()) {
      return rawRef.trim();
    }
    return "demo-member-01";
  }

  return null;
}

membershipRouter.get("/membership/status", (req, res) => {
  const memberRef = resolveMemberRef(req);
  if (!memberRef) {
    return res.status(401).json({ error: "unauthenticated", message: "Authentication required to query membership status." });
  }
  const status = membershipService.getStatus(memberRef);
  res.json(status);
});

membershipRouter.post("/membership/enroll", (req, res, next) => {
  try {
    const memberRef = resolveMemberRef(req);
    if (!memberRef) {
      return res.status(401).json({ error: "unauthenticated", message: "Valid institutional authentication token required for enrollment." });
    }
    const clientCommitment = req.body?.commitment;
    const result = membershipService.enroll(memberRef, clientCommitment);
    res.status(201).json(result);
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
    if (env.nodeEnv === "production" || process.env.NODE_ENV === "production") {
      if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: "unauthenticated", message: "Administrator authentication required to revoke members." });
      }
      const claims = authService.verifyToken(authHeader.substring(7).trim());
      if (claims.role !== "admin") {
        return res.status(403).json({ error: "forbidden", message: "Only administrators can revoke institutional memberships." });
      }
    }

    const memberRef = req.body?.memberRef || (req.headers["x-member-ref"] as string) || resolveMemberRef(req);
    const reason = req.body?.reason;
    if (!memberRef || typeof memberRef !== "string" || !memberRef.trim()) {
      return res.status(400).json({ error: "invalid_request", message: "Member reference is required." });
    }
    const result = membershipService.revoke(memberRef, reason);
    res.json(result);
  } catch (err) {
    if (err instanceof MembershipError) {
      return res.status(err.status).json({ error: err.code, message: err.message });
    }
    next(err);
  }
});

membershipRouter.post("/membership/validate", (req, res) => {
  const memberRef = resolveMemberRef(req);
  if (!memberRef) {
    return res.status(401).json({ error: "unauthenticated", message: "Authentication required to validate membership." });
  }
  const result = membershipService.validate(memberRef);
  res.json(result);
});
