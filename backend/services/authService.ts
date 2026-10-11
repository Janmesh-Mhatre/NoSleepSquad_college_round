import crypto from "node:crypto";
import { env } from "../config/env.js";

export type UserRole = "member" | "moderator" | "admin";

export const INTERNAL_JWT_ISSUER = "incognito-auth-service";
export const INTERNAL_JWT_AUDIENCE = "incognito-app";

export interface AuthClaims {
  sub: string;
  role: UserRole;
  email?: string;
  org?: string;
  iat: number;
  exp: number;
  iss: string;
  aud: string;
}

export class AuthError extends Error {
  constructor(public code: string, message: string, public status = 401) {
    super(message);
    this.name = "AuthError";
  }
}

export type TokenParams = Omit<AuthClaims, "iat" | "iss" | "aud" | "exp"> & {
  exp?: number;
  expiresInSeconds?: number;
  aud?: string;
};

export interface IAuthProvider {
  verifyToken(token: string): AuthClaims;
  generateToken(claims: TokenParams): string;
}

/**
 * Production-ready JWT Authentication Provider using HMAC-SHA256
 */
export class JwtAuthProvider implements IAuthProvider {
  private secret: Buffer;

  constructor(secretString?: string) {
    const rawSecret = secretString || env.authSecret;
    if (!rawSecret || rawSecret.length < 16) {
      throw new Error("AUTH_SECRET must be configured and at least 16 characters long.");
    }
    this.secret = Buffer.from(rawSecret, "utf-8");
  }

  generateToken(params: TokenParams): string {
    const now = Math.floor(Date.now() / 1000);
    const exp = params.exp || now + (params.expiresInSeconds ?? 3600);

    const header = { alg: "HS256", typ: "JWT" };
    const payload: AuthClaims = {
      sub: params.sub,
      role: params.role,
      email: params.email,
      org: params.org || "institutional-authority",
      iat: now,
      exp,
      iss: INTERNAL_JWT_ISSUER,
      aud: params.aud || INTERNAL_JWT_AUDIENCE,
    };

    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const signature = crypto
      .createHmac("sha256", this.secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest("base64url");

    return `${headerB64}.${payloadB64}.${signature}`;
  }

  verifyToken(token: string): AuthClaims {
    if (!token || typeof token !== "string") {
      throw new AuthError("invalid_token", "Authentication token is required.", 401);
    }

    const parts = token.split(".");
    if (parts.length !== 3) {
      throw new AuthError("malformed_token", "Token must be a valid 3-part signed JWT.", 401);
    }

    const [headerB64, payloadB64, signature] = parts;

    // Parse and validate header
    let header: { alg?: string; typ?: string };
    try {
      header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf-8"));
    } catch {
      throw new AuthError("malformed_header", "Token header could not be decoded.", 401);
    }

    if (!header || typeof header !== "object" || header.alg !== "HS256") {
      throw new AuthError("invalid_algorithm", "Unsupported or rejected signing algorithm. HS256 required.", 401);
    }

    // Verify cryptographic HMAC signature
    const expectedSig = crypto
      .createHmac("sha256", this.secret)
      .update(`${headerB64}.${payloadB64}`)
      .digest("base64url");

    const expectedBuf = Buffer.from(expectedSig);
    const actualBuf = Buffer.from(signature);

    if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
      throw new AuthError("invalid_signature", "Cryptographic signature validation failed.", 401);
    }

    // Parse payload
    let claims: AuthClaims & { nbf?: number };
    try {
      claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf-8"));
    } catch {
      throw new AuthError("malformed_payload", "Token claims payload could not be decoded.", 401);
    }

    // Verify claims structure
    if (!claims.sub || !claims.role || typeof claims.exp !== "number") {
      throw new AuthError("invalid_claims", "Required token claims (sub, role, exp) are missing.", 401);
    }

    if (!["member", "moderator", "admin"].includes(claims.role)) {
      throw new AuthError("invalid_role", "Token role must be member, moderator, or admin.", 401);
    }

    // Verify issuer unconditionally
    if (!claims.iss) {
      throw new AuthError("missing_issuer", "Token missing required issuer claim.", 401);
    }
    if (claims.iss !== INTERNAL_JWT_ISSUER) {
      throw new AuthError("invalid_issuer", "Token issuer is invalid.", 401);
    }

    // Verify audience unconditionally
    if (!(claims as any).aud) {
      throw new AuthError("missing_audience", "Token missing required audience claim.", 401);
    }
    if ((claims as any).aud !== INTERNAL_JWT_AUDIENCE) {
      throw new AuthError("invalid_audience", "Token audience is invalid.", 401);
    }

    const now = Math.floor(Date.now() / 1000);

    // Verify not-before
    if (typeof claims.nbf === "number" && claims.nbf > now) {
      throw new AuthError("token_not_active", "Token is not yet active.", 401);
    }

    // Verify expiration
    if (claims.exp <= now) {
      throw new AuthError("token_expired", "Authentication token has expired.", 401);
    }

    return claims;
  }
}

/**
 * Isolated Mock Authentication Provider for local testing/development.
 * Explicitly rejects initialization in deployed environments (staging / production).
 */
export class MockAuthProvider implements IAuthProvider {
  private jwtProvider: JwtAuthProvider;

  constructor() {
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
    if (isDeployed) {
      throw new Error("FATAL: MockAuthProvider is strictly prohibited in production and staging environments.");
    }
    this.jwtProvider = new JwtAuthProvider("mock-dev-testing-secret-only-never-in-prod!");
  }

  generateToken(params: TokenParams): string {
    return this.jwtProvider.generateToken(params);
  }

  verifyToken(token: string): AuthClaims {
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
    if (isDeployed) {
      throw new AuthError("mock_disabled_in_deployed", "Mock authentication disabled in deployed environments.", 401);
    }
    return this.jwtProvider.verifyToken(token);
  }
}

/**
 * Global authentication service singleton
 */
class AuthService {
  private provider: IAuthProvider;

  constructor() {
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
    const isDev = (process.env.NODE_ENV || "development").toLowerCase() === "development" || (process.env.NODE_ENV || "development").toLowerCase() === "test";
    const devAuthAllowed = isDev && (process.env.ALLOW_DEV_AUTH === "true" || process.env.DEV_AUTH_ENABLED === "true");

    if (env.authProvider === "mock" && !isDeployed && devAuthAllowed) {
      this.provider = new MockAuthProvider();
    } else {
      this.provider = new JwtAuthProvider();
    }
  }

  verifyToken(token: string): AuthClaims {
    return this.provider.verifyToken(token);
  }

  generateToken(params: TokenParams): string {
    return this.provider.generateToken(params);
  }

  /**
   * For testing purposes, allows explicitly switching or inspecting the provider
   */
  setProvider(provider: IAuthProvider) {
    this.provider = provider;
  }
}

export const authService = new AuthService();
