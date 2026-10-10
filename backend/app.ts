import cors from "cors";
import express, { type ErrorRequestHandler } from "express";
import { env } from "./config/env.js";
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

  // Development/Test token endpoint (strictly unavailable in production)
  if (env.nodeEnv !== "production") {
    app.post("/api/auth/dev-token", (req, res) => {
      const { role = "moderator", sub = "dev-user-01" } = req.body || {};
      if (!["member", "moderator", "admin"].includes(role)) {
        return res.status(400).json({ error: "invalid_role", message: "Role must be member, moderator, or admin." });
      }
      const token = authService.generateToken({ sub, role });
      res.json({ token, role, sub });
    });
  }

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
