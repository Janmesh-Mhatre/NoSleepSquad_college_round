import { Router } from "express";
import { membershipService, MembershipError } from "../services/membershipService.js";

export const membershipRouter = Router();

membershipRouter.get("/membership/status", (req, res) => {
  const memberRef = (req.query.ref as string) || (req.headers["x-member-ref"] as string) || "demo-member-01";
  const status = membershipService.getStatus(memberRef);
  res.json(status);
});

membershipRouter.post("/membership/enroll", (req, res, next) => {
  try {
    const memberRef = req.body?.memberRef || (req.headers["x-member-ref"] as string) || "demo-member-01";
    if (!memberRef || typeof memberRef !== "string" || !memberRef.trim()) {
      return res.status(400).json({ error: "invalid_request", message: "Member reference is required." });
    }
    const result = membershipService.enroll(memberRef);
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
    const memberRef = req.body?.memberRef || (req.headers["x-member-ref"] as string) || "demo-member-01";
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
  const memberRef = req.body?.memberRef || (req.headers["x-member-ref"] as string) || "demo-member-01";
  if (!memberRef || typeof memberRef !== "string" || !memberRef.trim()) {
    return res.status(400).json({ error: "invalid_request", message: "Member reference is required." });
  }
  const result = membershipService.validate(memberRef);
  res.json(result);
});
