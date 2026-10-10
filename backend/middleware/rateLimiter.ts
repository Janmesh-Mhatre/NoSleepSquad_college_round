import type { Request, Response, NextFunction } from "express";

interface RateLimitRecord {
  hits: number;
  resetTime: number;
}

export function createRateLimiter(options: {
  windowMs: number;
  max: number;
  message?: string;
}) {
  const { windowMs, max, message = "Too many requests. Please try again later." } = options;
  const store = new Map<string, RateLimitRecord>();

  // Periodically clean up expired entries every 5 minutes
  setInterval(() => {
    const now = Date.now();
    for (const [key, record] of store.entries()) {
      if (now > record.resetTime) {
        store.delete(key);
      }
    }
  }, 5 * 60 * 1000).unref();

  return (req: Request, res: Response, next: NextFunction) => {
    const ip = (req.headers["x-forwarded-for"] as string) || req.socket.remoteAddress || "127.0.0.1";
    const now = Date.now();

    let record = store.get(ip);
    if (!record || now > record.resetTime) {
      record = { hits: 1, resetTime: now + windowMs };
      store.set(ip, record);
    } else {
      record.hits += 1;
    }

    const remaining = Math.max(0, max - record.hits);
    res.setHeader("X-RateLimit-Limit", max);
    res.setHeader("X-RateLimit-Remaining", remaining);
    res.setHeader("X-RateLimit-Reset", Math.ceil(record.resetTime / 1000));

    if (record.hits > max) {
      const retryAfterSeconds = Math.ceil((record.resetTime - now) / 1000);
      res.setHeader("Retry-After", retryAfterSeconds);
      return res.status(429).json({
        error: "too_many_requests",
        message,
        retryAfter: retryAfterSeconds,
      });
    }

    next();
  };
}
