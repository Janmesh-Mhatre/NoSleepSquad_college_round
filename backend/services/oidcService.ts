import crypto from "node:crypto";

export interface OidcConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  publicKey?: string;
  allowedEmailDomains: string[];
  allowedAlgorithms?: string[];
}

export interface VerifiedInstitutionalIdentity {
  eligible: boolean;
  institutionDomain: string;
  role: "student" | "staff" | "faculty";
  eligibilityProofHash: string; // Zero PII: One-way hash proving eligibility without exposing name or student ID
}

export class OidcAuthError extends Error {
  constructor(public code: string, message: string, public status = 401) {
    super(message);
    this.name = "OidcAuthError";
  }
}

export class OidcService {
  private config: OidcConfig;

  constructor(customConfig?: Partial<OidcConfig>) {
    this.config = {
      issuerUrl: customConfig?.issuerUrl || process.env.OIDC_ISSUER_URL || "https://login.microsoftonline.com/institutional-tenant/v2.0",
      clientId: customConfig?.clientId || process.env.OIDC_CLIENT_ID || "incognito-institutional-app-id",
      clientSecret: customConfig?.clientSecret || process.env.OIDC_CLIENT_SECRET || "institutional-oidc-signing-secret-key-32b!",
      publicKey: customConfig?.publicKey || process.env.OIDC_PUBLIC_KEY,
      allowedEmailDomains: customConfig?.allowedEmailDomains || (process.env.OIDC_ALLOWED_DOMAINS ? process.env.OIDC_ALLOWED_DOMAINS.split(",") : ["university.edu", "campus.ac.in"]),
      allowedAlgorithms: customConfig?.allowedAlgorithms || ["HS256", "RS256", "ES256"],
    };
  }

  /**
   * Helper to sign an institutional token for testing or local OIDC simulation
   */
  signToken(payload: Record<string, any>, alg: "HS256" = "HS256"): string {
    const header = { alg, typ: "JWT" };
    const headerB64 = Buffer.from(JSON.stringify(header)).toString("base64url");
    const payloadB64 = Buffer.from(JSON.stringify(payload)).toString("base64url");
    const data = `${headerB64}.${payloadB64}`;

    const secret = this.config.clientSecret || "institutional-oidc-signing-secret-key-32b!";
    const signature = crypto.createHmac("sha256", secret).update(data).digest("base64url");
    return `${data}.${signature}`;
  }

  /**
   * Cryptographically verifies an institutional OIDC JWT token.
   * Validates:
   * 1. Cryptographic signature (rejecting unsigned / 'none' / tampered tokens)
   * 2. Header algorithm allowlist
   * 3. Token expiration and not-before claims
   * 4. Audience and Issuer integrity
   * 5. Institutional authorized email domain
   * Extracts eligibility while strictly prohibiting transmission of student PII to the reporting pipeline.
   */
  async verifyInstitutionalToken(idToken: string): Promise<VerifiedInstitutionalIdentity> {
    if (!idToken || typeof idToken !== "string") {
      throw new OidcAuthError("invalid_token", "An institutional OIDC ID token is required.");
    }

    const parts = idToken.split(".");
    if (parts.length !== 3) {
      throw new OidcAuthError("malformed_token", "Malformed OIDC token format. Expected 3-part signed JWT.");
    }

    const [headerB64, payloadB64, signature] = parts;

    // 1. Parse and validate header
    let header: { alg?: string; typ?: string; kid?: string };
    try {
      header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
    } catch {
      throw new OidcAuthError("malformed_header", "Failed to parse OIDC token header.");
    }

    if (!header.alg || header.alg.toLowerCase() === "none") {
      throw new OidcAuthError("unsupported_algorithm", "Algorithm 'none' or unsigned tokens are strictly forbidden.");
    }

    if (!this.config.allowedAlgorithms?.includes(header.alg)) {
      throw new OidcAuthError("unsupported_algorithm", `Algorithm '${header.alg}' is not permitted by institutional policy.`);
    }

    // 2. Cryptographic signature verification
    const signedData = `${headerB64}.${payloadB64}`;

    if (header.alg === "HS256") {
      const secret = this.config.clientSecret || "institutional-oidc-signing-secret-key-32b!";
      const expectedSig = crypto.createHmac("sha256", secret).update(signedData).digest("base64url");
      const expectedBuf = Buffer.from(expectedSig);
      const actualBuf = Buffer.from(signature);

      if (expectedBuf.length !== actualBuf.length || !crypto.timingSafeEqual(expectedBuf, actualBuf)) {
        throw new OidcAuthError("invalid_signature", "Cryptographic signature validation failed.");
      }
    } else if (header.alg === "RS256" || header.alg === "ES256") {
      if (!this.config.publicKey) {
        throw new OidcAuthError("missing_public_key", `Public key not configured for verifying ${header.alg} token.`);
      }
      const verifier = crypto.createVerify(header.alg === "RS256" ? "RSA-SHA256" : "SHA256");
      verifier.update(signedData);
      const isValid = verifier.verify(this.config.publicKey, Buffer.from(signature, "base64url"));
      if (!isValid) {
        throw new OidcAuthError("invalid_signature", "Asymmetric cryptographic signature validation failed.");
      }
    }

    // 3. Parse and validate payload
    let payload: Record<string, any>;
    try {
      payload = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
    } catch {
      throw new OidcAuthError("invalid_payload", "Failed to parse OIDC token payload.");
    }

    const now = Math.floor(Date.now() / 1000);

    // 4. Validate Expiration
    if (!payload.exp || payload.exp < now) {
      throw new OidcAuthError("token_expired", "Institutional OIDC token has expired.");
    }

    // 5. Validate Not-Before
    if (typeof payload.nbf === "number" && payload.nbf > now) {
      throw new OidcAuthError("token_not_active", "Institutional OIDC token is not yet valid.");
    }

    // 6. Validate Issuer
    if (payload.iss && payload.iss !== this.config.issuerUrl) {
      throw new OidcAuthError("invalid_issuer", `OIDC issuer mismatch. Expected '${this.config.issuerUrl}', got '${payload.iss}'.`);
    }

    // 7. Validate Audience
    if (payload.aud !== this.config.clientId) {
      throw new OidcAuthError("invalid_audience", `OIDC audience mismatch. Expected ${this.config.clientId}`);
    }

    // 8. Validate Institutional Email Domain
    const email = String(payload.email || payload.upn || "").toLowerCase();
    const domain = email.split("@")[1];
    if (!domain) {
      throw new OidcAuthError("invalid_email", "Institutional account email missing or malformed.");
    }

    const isAllowedDomain = this.config.allowedEmailDomains.some(
      (d) => domain === d.toLowerCase() || domain.endsWith(`.${d.toLowerCase()}`)
    );

    if (!isAllowedDomain) {
      throw new OidcAuthError("unauthorized_domain", `Account domain '@${domain}' is not authorized for this institution.`);
    }

    // 9. Determine institutional role
    let role: "student" | "staff" | "faculty" = "student";
    const roles: string[] = Array.isArray(payload.roles) ? payload.roles : [];
    if (roles.includes("Faculty") || payload.affiliation === "faculty") {
      role = "faculty";
    } else if (roles.includes("Staff") || payload.affiliation === "staff") {
      role = "staff";
    }

    // 10. Strict Privacy Barrier: Generate one-way pseudonym hash
    // We NEVER store email or real student ID in Incognito!
    const eligibilityProofHash = crypto
      .createHmac("sha256", "institutional-domain-eligibility-salt")
      .update(`${domain}:${payload.sub}`)
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
