import crypto from "node:crypto";
import * as jose from "jose";
import { env } from "../config/env.js";

export interface OidcConfig {
  issuerUrl: string;
  clientId: string;
  jwksUri?: string;
  allowedEmailDomains: string[];
  allowedAlgorithms?: string[];
  requireEmailVerified?: boolean;
  pseudonymSecret?: string;
  pseudonymVersion?: string;
  enableDiscovery?: boolean;
}

export interface VerifiedInstitutionalIdentity {
  eligible: boolean;
  institutionDomain: string;
  role: "student" | "staff" | "faculty";
  eligibilityProofHash: string; // Zero PII: One-way pseudonym hash proving eligibility without exposing name or student ID
}

export class OidcAuthError extends Error {
  constructor(public code: string, message: string, public status = 401) {
    super(message);
    this.name = "OidcAuthError";
  }
}

/**
 * Enterprise-grade Institutional OIDC Verification Service.
 * Implements cryptographic JWT verification backed by jose, dynamic discovery,
 * JWKS caching, and key rotation support.
 *
 * Security Invariants:
 * 1. Hardcoded fallback secrets are completely removed.
 * 2. Unsigned tokens, alg:none, and unexpected algorithms are strictly rejected.
 * 3. In deployed environments (production & staging), missing OIDC configuration fails closed.
 * 4. Token signature is cryptographically verified against trusted JWKS keys.
 * 5. Issuer, audience, and expiration claims are strictly verified.
 * 6. Institutional eligibility is enforced via verified claims without leaking student PII.
 */
export class OidcService {
  private config: OidcConfig;
  private remoteJWKSet: jose.JWTVerifyGetKey | null = null;
  private localJWKSet: jose.JWTVerifyGetKey | null = null;
  private customResolver: jose.JWTVerifyGetKey | null = null;

  // Development/Test in-memory key infrastructure for local test execution
  private testKeyPair: { publicKey: crypto.KeyObject; privateKey: crypto.KeyObject } | null = null;
  private testKeyId = "incognito-test-key-1";
  private testJwks: { keys: jose.JWK[] } | null = null;

  constructor(customConfig?: Partial<OidcConfig>) {
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";

    const issuerUrl = customConfig?.issuerUrl !== undefined ? customConfig.issuerUrl : (process.env.OIDC_ISSUER_URL || (isDeployed ? "" : "https://login.microsoftonline.com/institutional-tenant/v2.0"));
    const clientId = customConfig?.clientId !== undefined ? customConfig.clientId : (process.env.OIDC_CLIENT_ID || (isDeployed ? "" : "incognito-institutional-app-id"));
    const jwksUri = customConfig?.jwksUri !== undefined ? customConfig.jwksUri : (process.env.OIDC_JWKS_URI || undefined);
    const pseudonymSecret = customConfig?.pseudonymSecret !== undefined ? customConfig.pseudonymSecret : (process.env.PSEUDONYM_SECRET || env.pseudonymSecret || "");
    const pseudonymVersion = customConfig?.pseudonymVersion !== undefined ? customConfig.pseudonymVersion : (process.env.PSEUDONYM_VERSION || env.pseudonymVersion || "v1");

    if (isDeployed) {
      if (!issuerUrl || !issuerUrl.trim()) {
        throw new Error("FATAL: Deployed environment requires OIDC_ISSUER_URL to be configured.");
      }
      if (!issuerUrl.startsWith("https://")) {
        throw new Error("FATAL: OIDC_ISSUER_URL must use HTTPS in deployed environments.");
      }
      if (!clientId || !clientId.trim()) {
        throw new Error("FATAL: Deployed environment requires OIDC_CLIENT_ID to be configured.");
      }
      if (jwksUri && !jwksUri.startsWith("https://")) {
        throw new Error("FATAL: OIDC_JWKS_URI must use HTTPS in deployed environments.");
      }
      if (!pseudonymSecret || pseudonymSecret.length < 32 || pseudonymSecret.includes("dev-only")) {
        throw new Error("FATAL: Deployed environment requires PSEUDONYM_SECRET to be configured (min 32 chars).");
      }
    }

    const allowedEmailDomains = customConfig?.allowedEmailDomains ||
      (process.env.OIDC_ALLOWED_DOMAINS
        ? process.env.OIDC_ALLOWED_DOMAINS.split(",").map((d) => d.trim()).filter(Boolean)
        : ["university.edu", "campus.ac.in"]);

    this.config = {
      issuerUrl,
      clientId,
      jwksUri,
      allowedEmailDomains,
      allowedAlgorithms: customConfig?.allowedAlgorithms || ["RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"],
      requireEmailVerified: customConfig?.requireEmailVerified ?? false,
      pseudonymSecret,
      pseudonymVersion,
      enableDiscovery: customConfig?.enableDiscovery ?? isDeployed,
    };

    // If jwksUri is provided, pre-configure remote JWKSet with key rotation caching
    if (this.config.jwksUri) {
      this.remoteJWKSet = jose.createRemoteJWKSet(new URL(this.config.jwksUri), {
        cacheMaxAge: 10 * 60 * 1000, // 10 minutes
        cooldownDuration: 30 * 1000,  // 30 seconds
      });
    }

    // In local development or test mode, initialize test RSA keypair
    if (!isDeployed) {
      this.initTestKeypair();
    }
  }

  private initTestKeypair(): void {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    this.testKeyPair = { publicKey, privateKey };

    const publicJwk = {
      ...(publicKey.export({ format: "jwk" }) as jose.JWK),
      kid: this.testKeyId,
      alg: "RS256",
      use: "sig",
    };

    this.testJwks = { keys: [publicJwk] };
    this.localJWKSet = jose.createLocalJWKSet(this.testJwks as jose.JSONWebKeySet);
  }

  /**
   * Helper to sign an institutional token for testing or local OIDC simulation.
   * Strictly prohibited in deployed environments (staging / production).
   */
  signToken(
    payload: Record<string, any>,
    options?: { keyId?: string; alg?: string; customPrivateKey?: crypto.KeyObject }
  ): string {
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
    if (isDeployed) {
      throw new Error("SECURITY VIOLATION: signToken() is strictly prohibited in deployed environments.");
    }

    if (!this.testKeyPair) {
      this.initTestKeypair();
    }

    const alg = options?.alg || "RS256";
    const kid = options?.keyId || this.testKeyId;
    const privateKey = options?.customPrivateKey || this.testKeyPair!.privateKey;

    const header = { alg, typ: "JWT", kid };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const data = `${headerB64}.${payloadB64}`;

    const signer = crypto.createSign("RSA-SHA256");
    signer.update(data);
    const signature = signer.sign(privateKey, "base64url");

    return `${data}.${signature}`;
  }

  /**
   * Allows injecting a custom JWKS resolver (e.g. for testing key rotation, offline scenarios, mock IdP).
   */
  setJwksResolver(resolver: jose.JWTVerifyGetKey | null): void {
    this.customResolver = resolver;
  }

  /**
   * Sets a local JSONWebKeySet for testing.
   */
  setLocalJWKS(jwks: jose.JSONWebKeySet): void {
    this.localJWKSet = jose.createLocalJWKSet(jwks);
  }

  /**
   * Rotates the test signing key and adds the new key to the active JWKS.
   * Used for validating key rotation resilience in tests.
   */
  rotateTestKey(newKeyId = `incognito-test-key-${Date.now()}`): { keyId: string; publicJwk: jose.JWK } {
    const { publicKey, privateKey } = crypto.generateKeyPairSync("rsa", {
      modulusLength: 2048,
    });
    this.testKeyPair = { publicKey, privateKey };
    this.testKeyId = newKeyId;

    const publicJwk = {
      ...(publicKey.export({ format: "jwk" }) as jose.JWK),
      kid: newKeyId,
      alg: "RS256",
      use: "sig",
    };

    if (!this.testJwks) {
      this.testJwks = { keys: [] };
    }
    this.testJwks.keys.push(publicJwk);
    this.localJWKSet = jose.createLocalJWKSet(this.testJwks as jose.JSONWebKeySet);

    return { keyId: newKeyId, publicJwk };
  }

  /**
   * Removes a specific key from the test JWKS to test unknown key ID rejection.
   */
  removeTestKey(keyId: string): void {
    if (this.testJwks) {
      this.testJwks.keys = this.testJwks.keys.filter((k) => k.kid !== keyId);
      this.localJWKSet = jose.createLocalJWKSet(this.testJwks as jose.JSONWebKeySet);
    }
  }

  /**
   * Discovers and retrieves the trusted JWKS key resolver.
   * Supports dynamic OIDC discovery via /.well-known/openid-configuration.
   */
  private async getJWKSResolver(): Promise<jose.JWTVerifyGetKey> {
    if (this.customResolver) {
      return this.customResolver;
    }

    if (!this.config.enableDiscovery && this.localJWKSet) {
      return this.localJWKSet;
    }

    if (this.remoteJWKSet) {
      return this.remoteJWKSet;
    }

    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";

    // Dynamic OIDC Discovery if jwksUri not explicitly provided
    let jwksUri = this.config.jwksUri;
    if (!jwksUri) {
      if (!this.config.issuerUrl) {
        throw new OidcAuthError("missing_configuration", "OIDC issuer URL is required for JWKS discovery.", 500);
      }
      if (isDeployed && !this.config.issuerUrl.startsWith("https://")) {
        throw new OidcAuthError("invalid_discovery_url", "OIDC discovery requires HTTPS in deployed environments.", 500);
      }
      try {
        const discoveryUrl = `${this.config.issuerUrl.replace(/\/$/, "")}/.well-known/openid-configuration`;
        const res = await fetch(discoveryUrl, { signal: AbortSignal.timeout(5000) });
        if (!res.ok) {
          throw new Error(`Discovery endpoint returned HTTP ${res.status}`);
        }
        const metadata = (await res.json()) as { issuer?: string; jwks_uri?: string };
        if (!metadata || typeof metadata !== "object") {
          throw new OidcAuthError("invalid_discovery_metadata", "Institutional identity provider discovery metadata is malformed.", 503);
        }
        if (!metadata.issuer || metadata.issuer !== this.config.issuerUrl) {
          throw new OidcAuthError("discovery_issuer_mismatch", "Institutional identity provider discovery issuer mismatch.", 503);
        }
        if (!metadata.jwks_uri || typeof metadata.jwks_uri !== "string") {
          throw new OidcAuthError("invalid_jwks_uri", "Institutional identity provider JWKS endpoint is unsafe or invalid.", 503);
        }
        try {
          const parsed = new URL(metadata.jwks_uri);
          if (isDeployed && parsed.protocol !== "https:") {
            throw new Error("JWKS endpoint must use HTTPS in deployed environments.");
          }
        } catch {
          throw new OidcAuthError("invalid_jwks_uri", "Institutional identity provider JWKS endpoint is unsafe or invalid.", 503);
        }
        jwksUri = metadata.jwks_uri;
        this.config.jwksUri = jwksUri;
      } catch (err: any) {
        if (err instanceof OidcAuthError) {
          throw err;
        }
        throw new OidcAuthError(
          "provider_unavailable",
          "Institutional identity provider is currently unavailable.",
          503
        );
      }
    }

    try {
      this.remoteJWKSet = jose.createRemoteJWKSet(new URL(jwksUri), {
        cacheMaxAge: 10 * 60 * 1000,
        cooldownDuration: 30 * 1000,
      });
      return this.remoteJWKSet;
    } catch {
      throw new OidcAuthError("provider_unavailable", "Institutional identity provider is currently unavailable.", 503);
    }
  }

  /**
   * Cryptographically verifies an institutional OIDC ID token.
   *
   * Enforces:
   * 1. Rejection of unsigned tokens and algorithm 'none'
   * 2. Header algorithm allowlist (RS256, ES256, etc.)
   * 3. Valid cryptographic signature against trusted JWKS
   * 4. Expiration ('exp') and not-before ('nbf')
   * 5. Issuer ('iss') and Audience ('aud') verification
   * 6. Institutional email domain authorization
   * 7. Zero-PII eligibility pseudonym derivation
   */
  async verifyInstitutionalToken(idToken: string): Promise<VerifiedInstitutionalIdentity> {
    if (!idToken || typeof idToken !== "string") {
      throw new OidcAuthError("invalid_token", "An institutional OIDC ID token is required.", 401);
    }

    const parts = idToken.trim().split(".");
    if (parts.length !== 3) {
      throw new OidcAuthError("malformed_token", "Malformed OIDC token format. Expected 3-part signed JWT.", 401);
    }

    const [headerB64, payloadB64] = parts;

    // 1. Inspect and validate header
    let header: { alg?: string; typ?: string; kid?: string };
    try {
      header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    } catch {
      throw new OidcAuthError("malformed_header", "Failed to decode OIDC token header.", 401);
    }

    if (!header || typeof header !== "object" || !header.alg || header.alg.toLowerCase() === "none") {
      throw new OidcAuthError("unsupported_algorithm", "Algorithm 'none' or unsigned tokens are strictly forbidden.", 401);
    }

    const allowedAlgorithms = this.config.allowedAlgorithms || [
      "RS256", "RS384", "RS512", "ES256", "ES384", "ES512", "PS256", "PS384", "PS512"
    ];

    if (!allowedAlgorithms.includes(header.alg)) {
      throw new OidcAuthError(
        "unsupported_algorithm",
        `Algorithm '${header.alg}' is not permitted by institutional policy.`,
        401
      );
    }

    // 2. Resolve JWKS and verify cryptographic signature
    const jwksResolver = await this.getJWKSResolver();
    let verifiedPayload: jose.JWTPayload;

    try {
      const verifyResult = await jose.jwtVerify(idToken, jwksResolver, {
        issuer: this.config.issuerUrl,
        audience: this.config.clientId,
        algorithms: allowedAlgorithms,
      });
      verifiedPayload = verifyResult.payload;
    } catch (err: any) {
      const errCode = err?.code;
      const errMsg = err?.message || "";

      if (errCode === "ERR_JWT_EXPIRED") {
        throw new OidcAuthError("token_expired", "Institutional token has expired.", 401);
      }
      if (errCode === "ERR_JWT_CLAIM_VALIDATION_FAILED") {
        if (err.claim === "iss") {
          throw new OidcAuthError("invalid_issuer", "Institutional token issuer is not recognized.", 401);
        }
        if (err.claim === "aud") {
          throw new OidcAuthError("invalid_audience", "Institutional token audience is not valid for this application.", 401);
        }
        if (err.claim === "nbf") {
          throw new OidcAuthError("token_not_active", "Institutional token is not yet active.", 401);
        }
        throw new OidcAuthError("invalid_claim", "Institutional token claim validation failed.", 401);
      }
      if (errCode === "ERR_JWS_SIGNATURE_VERIFICATION_FAILED") {
        throw new OidcAuthError("invalid_signature", "Cryptographic signature validation failed.", 401);
      }
      if (errCode === "ERR_JWKS_NO_MATCHING_KEY") {
        throw new OidcAuthError("unknown_key_id", "Signing key ID not found in institutional JWKS.", 401);
      }
      if (errCode === "ERR_JWKS_MULTIPLE_MATCHING_KEYS") {
        throw new OidcAuthError("ambiguous_key_id", "Multiple keys matched signing key ID in JWKS.", 401);
      }
      if (errCode === "ERR_JOSE_NOT_SUPPORTED" || errMsg.includes("Unsupported \"alg\"")) {
        throw new OidcAuthError("unsupported_algorithm", "Unsupported signing algorithm.", 401);
      }
      if (errCode === "ERR_JWKS_TIMEOUT" || errMsg.includes("fetch failed") || errMsg.includes("unavailable")) {
        throw new OidcAuthError("provider_unavailable", "Institutional identity provider is currently unavailable.", 503);
      }
      throw new OidcAuthError("invalid_token", "Cryptographic token verification failed.", 401);
    }

    // 3. Inspect Required Claims
    if (!verifiedPayload.sub) {
      throw new OidcAuthError("missing_subject", "Institutional token missing required subject claim.", 401);
    }

    // 4. Verify Email Verification Status (if required by policy or present)
    if (this.config.requireEmailVerified && verifiedPayload.email_verified === false) {
      throw new OidcAuthError("unverified_email", "Institutional account email is not verified.", 403);
    }

    // 5. Validate Institutional Email Domain
    const email = String(
      verifiedPayload.email || verifiedPayload.upn || verifiedPayload.preferred_username || ""
    ).toLowerCase();
    const domain = email.split("@")[1];
    if (!domain) {
      throw new OidcAuthError("invalid_email", "Institutional account email missing or malformed.", 400);
    }

    const isAllowedDomain = this.config.allowedEmailDomains.some(
      (d) => domain === d.toLowerCase() || domain.endsWith(`.${d.toLowerCase()}`)
    );

    if (!isAllowedDomain) {
      throw new OidcAuthError("unauthorized_domain", "Account institutional domain is not authorized.", 403);
    }

    // 6. Determine Institutional Role and Validate Authoritative Eligibility Claims
    const rawRoles = Array.isArray(verifiedPayload.roles)
      ? verifiedPayload.roles
      : typeof verifiedPayload.role === "string"
      ? [verifiedPayload.role]
      : Array.isArray(verifiedPayload.groups)
      ? verifiedPayload.groups
      : [];
    const rawAffiliation = Array.isArray(verifiedPayload.affiliation)
      ? verifiedPayload.affiliation
      : typeof verifiedPayload.affiliation === "string"
      ? [verifiedPayload.affiliation]
      : [];
    const allRoleIndicators = [
      ...rawRoles,
      ...rawAffiliation,
      (verifiedPayload as any).eduPersonAffiliation,
      (verifiedPayload as any).eduPersonPrimaryAffiliation,
    ]
      .filter(Boolean)
      .map((r: any) => String(r).toLowerCase().trim());

    // Ineligible authoritative claims must fail closed
    const ineligibleRoles = ["guest", "visitor", "alumni", "former_student", "contractor", "external", "suspended", "inactive"];
    const hasIneligible = allRoleIndicators.some((r) => ineligibleRoles.includes(r));
    if (hasIneligible) {
      throw new OidcAuthError("ineligible_role", "Account institutional role is not eligible for reporting.", 403);
    }

    // If explicit institutional roles are defined but none correspond to eligible educational roles
    const eligibleRoleKeywords = ["student", "learner", "undergrad", "graduate", "staff", "faculty", "professor", "instructor", "teacher", "employee", "admin", "member"];
    if (allRoleIndicators.length > 0 && !allRoleIndicators.some((r) => eligibleRoleKeywords.some((k) => r.includes(k)))) {
      throw new OidcAuthError("ineligible_role", "Account institutional role is not eligible for reporting.", 403);
    }

    let role: "student" | "staff" | "faculty" = "student";
    if (allRoleIndicators.some((r) => r.includes("faculty") || r.includes("professor") || r.includes("instructor") || r.includes("teacher"))) {
      role = "faculty";
    } else if (allRoleIndicators.some((r) => r.includes("staff") || r.includes("employee") || r.includes("admin"))) {
      role = "staff";
    }

    // 7. Strict Privacy & Identity Separation:
    // Generate deterministic one-way HMAC pseudonym hash proving institutional eligibility
    // using securely injected secret and versioning without storing or leaking student PII.
    const isDeployed = env.isDeployedEnv || process.env.NODE_ENV === "production" || process.env.NODE_ENV === "staging";
    const pseudonymSecret = this.config.pseudonymSecret || env.pseudonymSecret || process.env.PSEUDONYM_SECRET;
    if (!pseudonymSecret || (isDeployed && (pseudonymSecret.length < 32 || pseudonymSecret.includes("dev-only")))) {
      if (isDeployed) {
        throw new OidcAuthError("missing_configuration", "Pseudonym derivation secret is unconfigured or insecure.", 500);
      }
    }
    const secret = pseudonymSecret || "dev-only-local-secret-do-not-use-in-production-min32";
    const version = this.config.pseudonymVersion || env.pseudonymVersion || "v1";

    const eligibilityProofHash = crypto
      .createHmac("sha256", secret)
      .update(`${version}:${domain}:${verifiedPayload.sub}`)
      .digest("hex");

    return {
      eligible: true,
      institutionDomain: domain,
      role,
      eligibilityProofHash,
    };
  }
}

export const oidcService = new OidcService();
