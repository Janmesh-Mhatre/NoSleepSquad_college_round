import type { Request, Response, NextFunction } from "express";
import { authService, AuthError, type UserRole, type AuthClaims } from "../services/authService.js";

// Extend express request with typed user
declare global {
  namespace Express {
    interface Request {
      user?: AuthClaims;
      staffRole?: UserRole;
    }
  }
}

export type StaffRole = "moderator" | "admin";

/**
 * Robust authentication and authorization middleware.
 * Verifies bearer token signatures and strictly enforces role permissions.
 * Rejects arbitrary client headers and never falls back silently.
 */
export function requireRole(allowedRoles: UserRole[]) {
  return (req: Request, res: Response, next: NextFunction) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
      return res.status(401).json({
        error: "unauthenticated",
        message: "Valid Bearer authentication token is required.",
      });
    }

    const token = authHeader.substring(7).trim();
    if (!token) {
      return res.status(401).json({
        error: "unauthenticated",
        message: "Bearer token cannot be empty.",
      });
    }

    try {
      const claims = authService.verifyToken(token);

      // Check role authorization
      if (!allowedRoles.includes(claims.role)) {
        return res.status(403).json({
          error: "unauthorized",
          message: "Insufficient permissions for requested resource.",
        });
      }

      // Attach verified principal to request
      req.user = claims;
      req.staffRole = claims.role;
      next();
    } catch (err) {
      if (err instanceof AuthError) {
        return res.status(err.status).json({
          error: err.code,
          message: err.message,
        });
      }
      return res.status(401).json({
        error: "invalid_token",
        message: "Authentication validation failed.",
      });
    }
  };
}
