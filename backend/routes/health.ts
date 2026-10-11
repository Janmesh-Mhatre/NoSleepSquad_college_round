import { Router } from "express";
import { getHealth } from "../services/healthService.js";

export const healthRouter = Router();

healthRouter.get("/health", (_req, res) => {
  res.json(getHealth());
});

healthRouter.get("/system/health", (_req, res) => {
  res.json(getHealth());
});

healthRouter.get("/system/status", (_req, res) => {
  res.json(getHealth());
});
