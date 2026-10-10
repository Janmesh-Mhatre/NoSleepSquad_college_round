import crypto from "node:crypto";

export interface OidcConfig {
  issuerUrl: string;
  clientId: string;
  clientSecret?: string;
  allowedEmailDomains: string[];
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
      clientSecret: customConfig?.clientSecret || process.env.OIDC_CLIENT_SECRET,
      allowedEmailDomains: customConfig?.allowedEmailDomains || (process.env.OIDC_ALLOWED_DOMAINS ? process.env.OIDC_ALLOWED_DOMAINS.split(",") : ["university.edu", "campus.ac.in"]),
    };
  }

  /**
   * Verifies an institutional OIDC JWT token.
   * Extracts eligibility while strictly prohibiting transmission of student PII to the reporting pipeline.
   */
  async verifyInstitutionalToken(idToken: string): Promise<VerifiedInstitutionalIdentity> {
    if (!idToken || typeof idToken !== "string") {
      throw new OidcAuthError("invalid_token", "An institutional OIDC ID token is required.");
    }

    const parts = idToken.split(".");
    if (parts.length !== 3) {
      throw new OidcAuthError("malformed_token", "Malformed OIDC token format.");
    }

    let payload: Record<string, any>;
    try {
      payload = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    } catch {
      throw new OidcAuthError("invalid_payload", "Failed to parse OIDC token payload.");
    }

    // 1. Validate Expiration
    const now = Math.floor(Date.now() / 1000);
    if (!payload.exp || payload.exp < now) {
      throw new OidcAuthError("token_expired", "Institutional OIDC token has expired.");
    }

    // 2. Validate Audience
    if (payload.aud !== this.config.clientId) {
      throw new OidcAuthError("invalid_audience", `OIDC audience mismatch. Expected ${this.config.clientId}`);
    }

    // 3. Validate Institutional Email Domain
    const email = String(payload.email || payload.upn || "").toLowerCase();
    const domain = email.split("@")[1];
    const isAllowedDomain = this.config.allowedEmailDomains.some((d) => domain === d.toLowerCase() || domain.endsWith(`.${d.toLowerCase()}`));

    if (!isAllowedDomain) {
      throw new OidcAuthError("unauthorized_domain", `Account domain '@${domain}' is not authorized for this institution.`);
    }

    // 4. Determine institutional role
    let role: "student" | "staff" | "faculty" = "student";
    const roles: string[] = Array.isArray(payload.roles) ? payload.roles : [];
    if (roles.includes("Faculty") || payload.affiliation === "faculty") {
      role = "faculty";
    } else if (roles.includes("Staff") || payload.affiliation === "staff") {
      role = "staff";
    }

    // 5. Strict Privacy Barrier: Generate one-way pseudonym hash
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
