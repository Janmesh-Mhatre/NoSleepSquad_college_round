import cors from "cors";
import express, { type ErrorRequestHandler } from "express";
import { env, assertEnvironmentSecurity } from "./config/env.js";
import { healthRouter } from "./routes/health.js";
import { membershipRouter } from "./routes/membership.js";
import { credentialRouter } from "./routes/credential.js";
import { reportsRouter } from "./routes/reports.js";
import { moderatorRouter } from "./routes/moderator.js";
import { auditRouter } from "./routes/audit.js";
import { securityRouter } from "./routes/security.js";
import { requireRole } from "./middleware/auth.js";
import { createRateLimiter } from "./middleware/rateLimiter.js";
import { authService } from "./services/authService.js";
import { oidcService, OidcAuthError } from "./services/oidcService.js";

export function createApp() {
  const app = express();
  app.disable("x-powered-by");

  app.use(
    cors({
      origin: (origin, callback) => {
        // Non-browser clients or same-origin send no Origin header.
        if (!origin || env.corsOrigins.includes(origin)) {
          return callback(null, true);
        }
        return callback(new Error("CORS origin not allowed by institutional policy"));
      },
      credentials: true,
      methods: ["GET", "POST", "OPTIONS"],
    }),
  );

  app.use((_req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    res.setHeader("X-Content-Type-Options", "nosniff");
    res.setHeader("X-Frame-Options", "DENY");
    res.setHeader("Content-Security-Policy", "default-src 'self'; object-src 'none'; frame-ancestors 'none';");
    res.setHeader("Referrer-Policy", "no-referrer");
    next();
  });

  app.use(express.json({ limit: "64kb" }));

  // Enforce startup security invariants across all environments
  assertEnvironmentSecurity();

  // Development/Test token endpoint (strictly development-only, requires explicit ALLOW_DEV_AUTH=true)
  app.post("/api/auth/dev-token", (req, res) => {
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
    const currentEnv = (process.env.NODE_ENV || "development").toLowerCase();
    const isDev = currentEnv === "development" || currentEnv === "test";
    const devAuthAllowed = isDev && (process.env.ALLOW_DEV_AUTH === "true" || process.env.DEV_AUTH_ENABLED === "true");

    if (isDeployed || !devAuthAllowed) {
      return res.status(403).json({
        error: "dev_auth_disabled",
        message: "Development authentication endpoints are strictly prohibited in deployed environments and require explicit ALLOW_DEV_AUTH=true in development.",
      });
    }

    const sub = typeof req.body?.sub === "string" && req.body.sub.trim() ? req.body.sub.trim() : "dev-user-01";
    const role = "member";
    const token = authService.generateToken({ sub, role });
    return res.json({ token, role, sub });
  });

  // Institutional OIDC Token Verification & Session Issuance endpoint
  app.post("/api/auth/oidc/verify", async (req, res) => {
    try {
      const authHeader = req.headers.authorization;
      const idToken =
        (req.body?.idToken as string) ||
        (authHeader && authHeader.startsWith("Bearer ") ? authHeader.substring(7).trim() : null);

      if (!idToken) {
        return res.status(400).json({
          error: "invalid_request",
          message: "Institutional OIDC ID token is required.",
        });
      }

      const identity = await oidcService.verifyInstitutionalToken(idToken);
      if (!identity.eligible) {
        return res.status(403).json({
          error: "ineligible",
          message: "Institutional account is not eligible for reporting.",
        });
      }

      // Issue authenticated member session token bound to the privacy-preserving eligibility hash
      const sessionToken = authService.generateToken({
        sub: identity.eligibilityProofHash,
        role: "member",
        org: identity.institutionDomain,
      });

      return res.json({
        eligible: true,
        institutionDomain: identity.institutionDomain,
        role: identity.role,
        sessionToken,
      });
    } catch (err: any) {
      if (err instanceof OidcAuthError) {
        return res.status(err.status).json({ error: err.code, message: err.message });
      }
      return res.status(401).json({ error: "invalid_token", message: "OIDC token verification failed." });
    }
  });

  // Rate Limiting
  const reportSubmissionLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    max: 30,
    message: "Too many submission attempts. Please wait before submitting another report.",
  });

  const reportStatusLimiter = createRateLimiter({
    windowMs: 60 * 1000,
    max: 60,
    message: "Too many status queries. Please wait before querying again.",
  });

  app.post("/api/reports", reportSubmissionLimiter);
  app.post("/api/reports/status", reportStatusLimiter);

  // Role-Based Access Control (RBAC)
  app.use("/api/moderator", requireRole(["moderator", "admin"]));
  app.use("/api/security", requireRole(["admin"]));
  app.use("/api/audit", requireRole(["admin", "moderator"]));

  // Mount routers
  app.use(healthRouter);
  app.use("/api", healthRouter);
  app.use("/api", membershipRouter);
  app.use("/api", credentialRouter);
  app.use("/api", reportsRouter);
  app.use("/api", moderatorRouter);
  app.use("/api", auditRouter);
  app.use("/api", securityRouter);

  app.use((_req, res) => {
    res.status(404).json({ error: "not_found", message: "Resource not found" });
  });

  // Security rule: Never log request bodies or headers. Log only the error message.
  const errorHandler: ErrorRequestHandler = (err, _req, res, _next) => {
    console.error("Internal service error:", err instanceof Error ? err.message : "unknown");
    res.status(500).json({ error: "internal_error", message: "An internal server error occurred." });
  };
  app.use(errorHandler);

  return app;
}
