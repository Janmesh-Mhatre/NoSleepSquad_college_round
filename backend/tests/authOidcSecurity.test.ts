import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import http from "node:http";
import * as jose from "jose";
import { createApp } from "../app.js";
import { authService, JwtAuthProvider, AuthError } from "../services/authService.js";
import { oidcService, OidcService, OidcAuthError } from "../services/oidcService.js";
import { assertEnvironmentSecurity, env } from "../config/env.js";
import { zkProofService } from "../services/zkProofService.js";
import { reportService, ReportError } from "../services/reportService.js";
import { Identity } from "@semaphore-protocol/core";

// Helper to start ephemeral server for HTTP testing
async function withServer<T>(app: any, fn: (baseUrl: string) => Promise<T>): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const server = app.listen(0, async () => {
      const address = server.address() as any;
      const baseUrl = `http://127.0.0.1:${address.port}`;
      try {
        const result = await fn(baseUrl);
        server.close(() => resolve(result));
      } catch (err) {
        server.close(() => reject(err));
      }
    });
  });
}

test("AUTHENTICATION & OIDC SECURITY HARDENING SUITE", async (suite) => {
  const jwtProvider = new JwtAuthProvider("security-hardening-test-secret-min32ch!");
  const memberToken = jwtProvider.generateToken({ sub: "sec-member-01", role: "member" });
  const moderatorToken = jwtProvider.generateToken({ sub: "sec-moderator-01", role: "moderator" });
  const adminToken = jwtProvider.generateToken({ sub: "sec-admin-01", role: "admin" });

  // Point authService to test provider for predictable signatures
  authService.setProvider(jwtProvider);

  // =========================================================================
  // SECTION 1: DEVELOPMENT BYPASS & ENVIRONMENT SAFETY TESTS
  // =========================================================================
  await suite.test("1. Environment Safety & Startup Guards", async (t) => {
    const origEnv = process.env.NODE_ENV;
    const origDevAuth = process.env.ALLOW_DEV_AUTH;
    const origDevAuthEnabled = process.env.DEV_AUTH_ENABLED;
    const origAuthSecret = process.env.AUTH_SECRET;
    const origEncKey = process.env.ENCRYPTION_KEY;
    const origOidcIssuer = process.env.OIDC_ISSUER_URL;
    const origOidcClient = process.env.OIDC_CLIENT_ID;

    try {
      // 1.1 In staging, ALLOW_DEV_AUTH=true must throw and refuse startup
      process.env.NODE_ENV = "staging";
      process.env.ALLOW_DEV_AUTH = "true";
      assert.throws(
        () => assertEnvironmentSecurity(),
        /FATAL SECURITY MISCONFIGURATION.*ALLOW_DEV_AUTH.*prohibited in deployed environments/
      );

      // 1.2 In production, DEV_AUTH_ENABLED=true must throw and refuse startup
      process.env.NODE_ENV = "production";
      process.env.ALLOW_DEV_AUTH = "false";
      process.env.DEV_AUTH_ENABLED = "true";
      assert.throws(
        () => assertEnvironmentSecurity(),
        /FATAL SECURITY MISCONFIGURATION.*ALLOW_DEV_AUTH.*prohibited in deployed environments/
      );

      // 1.3 In staging, missing OIDC_ISSUER_URL fails closed
      process.env.NODE_ENV = "staging";
      process.env.ALLOW_DEV_AUTH = "false";
      process.env.DEV_AUTH_ENABLED = "false";
      process.env.AUTH_SECRET = "secure-production-auth-secret-min32-chars!";
      process.env.ENCRYPTION_KEY = "secure-production-encryption-key-min32!";
      delete process.env.OIDC_ISSUER_URL;
      assert.throws(
        () => assertEnvironmentSecurity(),
        /FATAL: STAGING requires OIDC_ISSUER_URL to be configured/
      );

      // 1.4 In production, missing OIDC_CLIENT_ID fails closed
      process.env.NODE_ENV = "production";
      process.env.OIDC_ISSUER_URL = "https://identity.university.edu";
      delete process.env.OIDC_CLIENT_ID;
      assert.throws(
        () => assertEnvironmentSecurity(),
        /FATAL: PRODUCTION requires OIDC_CLIENT_ID to be configured/
      );

      // 1.5 In production, missing or short PSEUDONYM_SECRET fails closed
      process.env.NODE_ENV = "production";
      process.env.OIDC_ISSUER_URL = "https://identity.university.edu";
      process.env.OIDC_CLIENT_ID = "incognito-app";
      delete process.env.PSEUDONYM_SECRET;
      assert.throws(
        () => assertEnvironmentSecurity(),
        /FATAL: PRODUCTION requires PSEUDONYM_SECRET to be configured \(min 32 chars\)/
      );

      // 1.6 In production, non-HTTPS OIDC_ISSUER_URL fails closed
      process.env.PSEUDONYM_SECRET = "secure-production-pseudonym-secret-min32-chars!";
      process.env.OIDC_ISSUER_URL = "http://insecure-idp.university.edu";
      assert.throws(
        () => assertEnvironmentSecurity(),
        /FATAL: PRODUCTION OIDC_ISSUER_URL must use HTTPS/
      );
    } finally {
      process.env.NODE_ENV = origEnv;
      process.env.ALLOW_DEV_AUTH = origDevAuth;
      process.env.DEV_AUTH_ENABLED = origDevAuthEnabled;
      process.env.AUTH_SECRET = origAuthSecret;
      process.env.ENCRYPTION_KEY = origEncKey;
      process.env.OIDC_ISSUER_URL = origOidcIssuer;
      process.env.OIDC_CLIENT_ID = origOidcClient;
    }
  });

  await suite.test("2. Dev Token Endpoint Environment Enforcement", async (t) => {
    const origEnv = process.env.NODE_ENV;
    const origDevAuth = process.env.ALLOW_DEV_AUTH;

    try {
      const app = createApp();

      // 2.1 Dev token works ONLY when ALLOW_DEV_AUTH=true in development
      process.env.NODE_ENV = "development";
      process.env.ALLOW_DEV_AUTH = "true";
      await withServer(app, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/auth/dev-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-student" }),
        });
        assert.strictEqual(res.status, 200);
        const data = await res.json() as any;
        assert.ok(data.token);
        assert.strictEqual(data.sub, "dev-student");
      });

      // 2.2 Dev token FAILS in development if ALLOW_DEV_AUTH is not explicitly true
      process.env.NODE_ENV = "development";
      process.env.ALLOW_DEV_AUTH = "false";
      await withServer(app, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/auth/dev-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-student" }),
        });
        assert.strictEqual(res.status, 403);
        const data = await res.json() as any;
        assert.strictEqual(data.error, "dev_auth_disabled");
      });

      // 2.3 Dev token FAILS in staging
      process.env.NODE_ENV = "staging";
      process.env.ALLOW_DEV_AUTH = "false";
      await withServer(app, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/auth/dev-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-student" }),
        });
        assert.strictEqual(res.status, 403);
      });

      // 2.4 Dev token FAILS in production
      process.env.NODE_ENV = "production";
      process.env.ALLOW_DEV_AUTH = "false";
      await withServer(app, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/auth/dev-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-student" }),
        });
        assert.strictEqual(res.status, 403);
      });

      // 2.5 Dedicated dev moderator token: works in dev + ALLOW_DEV_AUTH=true, server hardcodes role="moderator", caller cannot choose admin
      process.env.NODE_ENV = "development";
      process.env.ALLOW_DEV_AUTH = "true";
      await withServer(app, async (baseUrl) => {
        // Normal request
        const res = await fetch(`${baseUrl}/api/auth/dev-moderator-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-moderator-01" }),
        });
        assert.strictEqual(res.status, 200);
        const data = await res.json() as any;
        assert.ok(data.token);
        assert.strictEqual(data.role, "moderator");
        assert.strictEqual(data.sub, "dev-moderator-01");

        // Token works against protected moderator route
        const modRes = await fetch(`${baseUrl}/api/moderator/metrics`, {
          headers: { Authorization: `Bearer ${data.token}` },
        });
        assert.strictEqual(modRes.status, 200);

        // Caller cannot choose admin role
        const hijackRes = await fetch(`${baseUrl}/api/auth/dev-moderator-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "attacker", role: "admin" }),
        });
        assert.strictEqual(hijackRes.status, 200);
        const hijackData = await hijackRes.json() as any;
        assert.strictEqual(hijackData.role, "moderator", "Server must strictly hardcode role to moderator");

        // Verified token cannot access admin routes
        const adminRes = await fetch(`${baseUrl}/api/security/posture`, {
          headers: { Authorization: `Bearer ${hijackData.token}` },
        });
        assert.strictEqual(adminRes.status, 403, "Moderator token cannot access admin routes");
      });

      // 2.6 Dev moderator token FAILS with 403 in staging
      process.env.NODE_ENV = "staging";
      process.env.ALLOW_DEV_AUTH = "false";
      await withServer(app, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/auth/dev-moderator-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-moderator-01" }),
        });
        assert.strictEqual(res.status, 403);
      });

      // 2.7 Dev moderator token FAILS with 403 in production
      process.env.NODE_ENV = "production";
      process.env.ALLOW_DEV_AUTH = "false";
      await withServer(app, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/auth/dev-moderator-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-moderator-01" }),
        });
        assert.strictEqual(res.status, 403);
      });

      // 2.8 Dev admin token: POST /api/auth/dev-token with role="admin" yields admin JWT and grants access to /api/security/tests and /api/system/status
      process.env.NODE_ENV = "development";
      process.env.ALLOW_DEV_AUTH = "true";
      await withServer(app, async (baseUrl) => {
        const res = await fetch(`${baseUrl}/api/auth/dev-token`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sub: "dev-admin-01", role: "admin" }),
        });
        assert.strictEqual(res.status, 200);
        const data = await res.json() as any;
        assert.ok(data.token);
        assert.strictEqual(data.role, "admin");
        assert.strictEqual(data.sub, "dev-admin-01");

        // Admin JWT claims verification
        const claims = authService.verifyToken(data.token);
        assert.strictEqual(claims.role, "admin");

        // Access /api/security/tests with admin token -> 200 OK (no 403)
        const secRes = await fetch(`${baseUrl}/api/security/tests`, {
          headers: { Authorization: `Bearer ${data.token}` },
        });
        assert.strictEqual(secRes.status, 200);

        // Access /api/system/status with admin token -> 200 OK (no 403)
        const sysRes = await fetch(`${baseUrl}/api/system/status`, {
          headers: { Authorization: `Bearer ${data.token}` },
        });
        assert.strictEqual(sysRes.status, 200);

        // Unauthenticated access to /api/system/status fails with 401
        const unauthSys = await fetch(`${baseUrl}/api/system/status`);
        assert.strictEqual(unauthSys.status, 401);

        // Moderator token access to /api/security/tests fails with 403
        const modToken = authService.generateToken({ sub: "mod-test", role: "moderator" });
        const modOnAdmin = await fetch(`${baseUrl}/api/security/tests`, {
          headers: { Authorization: `Bearer ${modToken}` },
        });
        assert.strictEqual(modOnAdmin.status, 403);
      });
    } finally {
      process.env.NODE_ENV = origEnv;
      process.env.ALLOW_DEV_AUTH = origDevAuth;
    }
  });

  await suite.test("3. Membership Routes Reject Caller-Controlled Identity & Demo Fallbacks in Deployed Environments", async (t) => {
    const origEnv = process.env.NODE_ENV;
    const origDevAuth = process.env.ALLOW_DEV_AUTH;

    try {
      const app = createApp();

      // Test across both deployed environments: staging and production
      for (const targetEnv of ["staging", "production"]) {
        process.env.NODE_ENV = targetEnv;
        process.env.ALLOW_DEV_AUTH = "false";

        await withServer(app, async (baseUrl) => {
          // 3.1 Unauthenticated GET /membership/status fails with 401 (never defaults to demo-member-01)
          const res1 = await fetch(`${baseUrl}/api/membership/status`);
          assert.strictEqual(res1.status, 401, `Status must return 401 in ${targetEnv}`);

          // 3.2 Caller-supplied x-member-ref cannot establish identity
          const res2 = await fetch(`${baseUrl}/api/membership/status`, {
            headers: { "x-member-ref": "forged-victim-id" },
          });
          assert.strictEqual(res2.status, 401, `x-member-ref must be ignored in ${targetEnv}`);

          // 3.3 Caller-supplied query param cannot establish identity
          const res3 = await fetch(`${baseUrl}/api/membership/status?ref=forged-victim-id`);
          assert.strictEqual(res3.status, 401, `Query ref must be ignored in ${targetEnv}`);

          // 3.4 Unauthenticated GET /credential/status fails with 401
          const res4 = await fetch(`${baseUrl}/api/credential/status`);
          assert.strictEqual(res4.status, 401, `Credential status must return 401 in ${targetEnv}`);

          // 3.5 Caller-supplied body.memberRef on unauthenticated POST /membership/enroll fails with 401
          const res5 = await fetch(`${baseUrl}/api/membership/enroll`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ memberRef: "unauthorized-member", commitment: "12345" }),
          });
          assert.strictEqual(res5.status, 401, `Enroll must return 401 for caller-supplied memberRef in ${targetEnv}`);

          // 3.6 POST /membership/revoke without admin token fails with 401 in staging & production
          const res6 = await fetch(`${baseUrl}/api/membership/revoke`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ memberRef: "some-member" }),
          });
          assert.strictEqual(res6.status, 401, `Revoke without admin token must return 401 in ${targetEnv}`);

          // 3.7 POST /membership/revoke with non-admin token fails with 403
          const res7 = await fetch(`${baseUrl}/api/membership/revoke`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${memberToken}`,
            },
            body: JSON.stringify({ memberRef: "some-member" }),
          });
          assert.strictEqual(res7.status, 403, `Revoke with member token must return 403 in ${targetEnv}`);
        });
      }
    } finally {
      process.env.NODE_ENV = origEnv;
      process.env.ALLOW_DEV_AUTH = origDevAuth;
    }
  });

  await suite.test("4. ZK Proof Enforcement Cannot Be Bypassed in Staging", async (t) => {
    const origEnv = process.env.NODE_ENV;

    try {
      process.env.NODE_ENV = "staging";

      // Attempt to submit report without ZK proof in staging
      await assert.rejects(
        async () => {
          await reportService.submitReport({
            categoryId: "cat-harassment",
            body: "Report body without ZK proof attempt in staging",
          });
        },
        (err: any) => err instanceof ReportError && err.code === "invalid_proof"
      );
    } finally {
      process.env.NODE_ENV = origEnv;
    }
  });

  await suite.test("5. Moderator & RBAC Header Forgery Rejection", async (t) => {
    const app = createApp();

    await withServer(app, async (baseUrl) => {
      // 5.1 X-Staff-Role header does not grant moderator access
      const res1 = await fetch(`${baseUrl}/api/moderator/reports`, {
        headers: { "x-staff-role": "moderator" },
      });
      assert.strictEqual(res1.status, 401, "Client header X-Staff-Role must be rejected with 401");

      // 5.2 X-Staff-Role header does not grant admin access
      const res2 = await fetch(`${baseUrl}/api/security/tests`, {
        headers: { "x-staff-role": "admin" },
      });
      assert.strictEqual(res2.status, 401, "Client header X-Staff-Role must be rejected with 401");

      // 5.3 Moderator attempting to access admin-only endpoint receives 403
      const res3 = await fetch(`${baseUrl}/api/security/tests`, {
        headers: { Authorization: `Bearer ${moderatorToken}` },
      });
      assert.strictEqual(res3.status, 403, "Moderator accessing admin endpoint must be rejected with 403");

      // 5.4 Admin accessing admin endpoint receives 200
      const res4 = await fetch(`${baseUrl}/api/security/tests`, {
        headers: { Authorization: `Bearer ${adminToken}` },
      });
      assert.strictEqual(res4.status, 200, "Admin accessing admin endpoint must succeed with 200");
    });
  });

  // =========================================================================
  // SECTION 2: JWT CRYPTOGRAPHIC VERIFICATION TESTS
  // =========================================================================
  await suite.test("6. JWT Signature, Algorithm & Claims Verification", async () => {
    // 6.1 Valid signed token succeeds
    const claims = jwtProvider.verifyToken(memberToken);
    assert.strictEqual(claims.sub, "sec-member-01");
    assert.strictEqual(claims.role, "member");

    // 6.2 Modified payload fails cryptographic signature verification
    const parts = memberToken.split(".");
    const tamperedPayloadB64 = Buffer.from(
      JSON.stringify({ sub: "sec-member-01", role: "admin", exp: Math.floor(Date.now() / 1000) + 3600 })
    ).toString("base64url");
    const tamperedPayloadToken = `${parts[0]}.${tamperedPayloadB64}.${parts[2]}`;
    assert.throws(
      () => jwtProvider.verifyToken(tamperedPayloadToken),
      (err: any) => err instanceof AuthError && err.code === "invalid_signature"
    );

    // 6.3 Invalid signature fails
    const tamperedSigToken = `${parts[0]}.${parts[1]}.invalid_signature_bytes`;
    assert.throws(
      () => jwtProvider.verifyToken(tamperedSigToken),
      (err: any) => err instanceof AuthError && err.code === "invalid_signature"
    );

    // 6.4 Algorithm 'none' is rejected
    const noneHeader = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
    const noneToken = `${noneHeader}.${parts[1]}.`;
    assert.throws(
      () => jwtProvider.verifyToken(noneToken),
      (err: any) => err instanceof AuthError && (err.code === "invalid_algorithm" || err.code === "unsupported_algorithm")
    );

    // 6.5 Wrong algorithm rejected
    const hs512Header = Buffer.from(JSON.stringify({ alg: "HS512", typ: "JWT" })).toString("base64url");
    const wrongAlgToken = `${hs512Header}.${parts[1]}.${parts[2]}`;
    assert.throws(
      () => jwtProvider.verifyToken(wrongAlgToken),
      (err: any) => err instanceof AuthError && err.code === "invalid_algorithm"
    );

    // 6.6 Expired token rejected
    const expiredToken = jwtProvider.generateToken({
      sub: "expired-user",
      role: "member",
      exp: Math.floor(Date.now() / 1000) - 30,
    });
    assert.throws(
      () => jwtProvider.verifyToken(expiredToken),
      (err: any) => err instanceof AuthError && err.code === "token_expired"
    );

    // 6.7 Missing issuer rejected
    const now = Math.floor(Date.now() / 1000);
    const missingIssPayload = Buffer.from(
      JSON.stringify({ sub: "u1", role: "member", exp: now + 3600, aud: "incognito-app" })
    ).toString("base64url");
    const missingIssSig = crypto
      .createHmac("sha256", "security-hardening-test-secret-min32ch!")
      .update(`${parts[0]}.${missingIssPayload}`)
      .digest("base64url");
    assert.throws(
      () => jwtProvider.verifyToken(`${parts[0]}.${missingIssPayload}.${missingIssSig}`),
      (err: any) => err instanceof AuthError && err.code === "missing_issuer"
    );

    // 6.8 Missing audience rejected
    const missingAudPayload = Buffer.from(
      JSON.stringify({ sub: "u1", role: "member", exp: now + 3600, iss: "incognito-auth-service" })
    ).toString("base64url");
    const missingAudSig = crypto
      .createHmac("sha256", "security-hardening-test-secret-min32ch!")
      .update(`${parts[0]}.${missingAudPayload}`)
      .digest("base64url");
    assert.throws(
      () => jwtProvider.verifyToken(`${parts[0]}.${missingAudPayload}.${missingAudSig}`),
      (err: any) => err instanceof AuthError && err.code === "missing_audience"
    );

    // 6.9 Wrong issuer rejected
    const wrongIssPayload = Buffer.from(
      JSON.stringify({ sub: "u1", role: "member", exp: now + 3600, iss: "evil-auth-service", aud: "incognito-app" })
    ).toString("base64url");
    const wrongIssSig = crypto
      .createHmac("sha256", "security-hardening-test-secret-min32ch!")
      .update(`${parts[0]}.${wrongIssPayload}`)
      .digest("base64url");
    assert.throws(
      () => jwtProvider.verifyToken(`${parts[0]}.${wrongIssPayload}.${wrongIssSig}`),
      (err: any) => err instanceof AuthError && err.code === "invalid_issuer"
    );

    // 6.10 Wrong audience rejected
    const wrongAudPayload = Buffer.from(
      JSON.stringify({ sub: "u1", role: "member", exp: now + 3600, iss: "incognito-auth-service", aud: "wrong-app" })
    ).toString("base64url");
    const wrongAudSig = crypto
      .createHmac("sha256", "security-hardening-test-secret-min32ch!")
      .update(`${parts[0]}.${wrongAudPayload}`)
      .digest("base64url");
    assert.throws(
      () => jwtProvider.verifyToken(`${parts[0]}.${wrongAudPayload}.${wrongAudSig}`),
      (err: any) => err instanceof AuthError && err.code === "invalid_audience"
    );

    // 6.11 Future not-before (nbf) rejected
    const futureNbfPayload = Buffer.from(
      JSON.stringify({ sub: "u1", role: "member", exp: now + 3600, iss: "incognito-auth-service", aud: "incognito-app", nbf: now + 600 })
    ).toString("base64url");
    const futureNbfSig = crypto
      .createHmac("sha256", "security-hardening-test-secret-min32ch!")
      .update(`${parts[0]}.${futureNbfPayload}`)
      .digest("base64url");
    assert.throws(
      () => jwtProvider.verifyToken(`${parts[0]}.${futureNbfPayload}.${futureNbfSig}`),
      (err: any) => err instanceof AuthError && err.code === "token_not_active"
    );

    // 6.12 Malformed payload (non-JSON base64) rejected
    const malformedPayloadB64 = Buffer.from("this is definitely not valid json {{{").toString("base64url");
    const malformedPayloadSig = crypto
      .createHmac("sha256", "security-hardening-test-secret-min32ch!")
      .update(`${parts[0]}.${malformedPayloadB64}`)
      .digest("base64url");
    assert.throws(
      () => jwtProvider.verifyToken(`${parts[0]}.${malformedPayloadB64}.${malformedPayloadSig}`),
      (err: any) => err instanceof AuthError && err.code === "malformed_payload"
    );

    // 6.13 Missing required claims (sub missing) fails
    const missingSubPayload = Buffer.from(
      JSON.stringify({ role: "member", exp: now + 3600, iss: "incognito-auth-service", aud: "incognito-app" })
    ).toString("base64url");
    const missingSubSig = crypto
      .createHmac("sha256", "security-hardening-test-secret-min32ch!")
      .update(`${parts[0]}.${missingSubPayload}`)
      .digest("base64url");
    assert.throws(
      () => jwtProvider.verifyToken(`${parts[0]}.${missingSubPayload}.${missingSubSig}`),
      (err: any) => err instanceof AuthError && err.code === "invalid_claims"
    );

    // 6.14 Malformed JWT fails
    assert.throws(
      () => jwtProvider.verifyToken("not-a-valid-jwt"),
      (err: any) => err instanceof AuthError && err.code === "malformed_token"
    );
  });

  // =========================================================================
  // SECTION 3: INSTITUTIONAL OIDC & JWKS ROTATION TESTS
  // =========================================================================
  await suite.test("7. Institutional OIDC Verification with jose, JWKS & Key Rotation", async (t) => {
    const oidcTestService = new OidcService({
      issuerUrl: "https://identity.university.edu/v2.0",
      clientId: "incognito-institutional-app-id",
      allowedEmailDomains: ["university.edu"],
      allowedAlgorithms: ["RS256"],
    });

    const now = Math.floor(Date.now() / 1000);
    const validOidcPayload = {
      sub: "student-sub-774411",
      email: "student77@university.edu",
      aud: "incognito-institutional-app-id",
      iss: "https://identity.university.edu/v2.0",
      exp: now + 3600,
      roles: ["Student"],
    };

    // 7.1 Valid institutional token succeeds and derives zero-PII pseudonym hash
    const validToken = oidcTestService.signToken(validOidcPayload);
    const result = await oidcTestService.verifyInstitutionalToken(validToken);
    assert.strictEqual(result.eligible, true);
    assert.strictEqual(result.institutionDomain, "university.edu");
    assert.strictEqual(result.role, "student");
    assert.ok(result.eligibilityProofHash);
    assert.ok(!result.eligibilityProofHash.includes("student-sub"));
    assert.ok(!result.eligibilityProofHash.includes("university.edu"));

    // 7.2 Unknown key ID (kid not found in JWKS) fails
    const unknownKidToken = oidcTestService.signToken(validOidcPayload, { keyId: "untrusted-external-kid-999" });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(unknownKidToken),
      (err: any) => err instanceof OidcAuthError && err.code === "unknown_key_id"
    );

    // 7.3 Key rotation test: rotate test key, sign with new key, verify succeeds
    const rotated = oidcTestService.rotateTestKey("rotated-key-v2");
    assert.strictEqual(rotated.keyId, "rotated-key-v2");

    const rotatedToken = oidcTestService.signToken(validOidcPayload, { keyId: "rotated-key-v2" });
    const rotatedResult = await oidcTestService.verifyInstitutionalToken(rotatedToken);
    assert.strictEqual(rotatedResult.eligible, true);

    // 7.4 Expired OIDC token fails
    const expiredOidcToken = oidcTestService.signToken({
      ...validOidcPayload,
      exp: now - 60,
    });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(expiredOidcToken),
      (err: any) => err instanceof OidcAuthError && err.code === "token_expired"
    );

    // 7.5 Wrong issuer fails
    const wrongIssToken = oidcTestService.signToken({
      ...validOidcPayload,
      iss: "https://attacker-idp.evil.com",
    });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(wrongIssToken),
      (err: any) => err instanceof OidcAuthError && err.code === "invalid_issuer"
    );

    // 7.6 Wrong audience fails
    const wrongAudToken = oidcTestService.signToken({
      ...validOidcPayload,
      aud: "wrong-application-client-id",
    });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(wrongAudToken),
      (err: any) => err instanceof OidcAuthError && err.code === "invalid_audience"
    );

    // 7.7 Unauthorized email domain fails
    const foreignDomainToken = oidcTestService.signToken({
      ...validOidcPayload,
      email: "attacker@external-domain.com",
    });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(foreignDomainToken),
      (err: any) => err instanceof OidcAuthError && err.code === "unauthorized_domain"
    );

    // 7.8 Provider unavailable: custom resolver throws network error
    oidcTestService.setJwksResolver(async () => {
      throw new Error("fetch failed: connection refused");
    });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(validToken),
      (err: any) => err instanceof OidcAuthError && err.code === "provider_unavailable" && err.status === 503
    );

    // Reset resolver to local JWKS
    oidcTestService.setJwksResolver(null);

    // 7.9 Authoritative Ineligible Role rejection (e.g. Guest, Alumni, Contractor)
    const guestToken = oidcTestService.signToken({
      ...validOidcPayload,
      roles: ["Guest"],
    });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(guestToken),
      (err: any) => err instanceof OidcAuthError && err.code === "ineligible_role" && err.status === 403
    );

    const alumniToken = oidcTestService.signToken({
      ...validOidcPayload,
      roles: ["Alumni"],
    });
    await assert.rejects(
      async () => oidcTestService.verifyInstitutionalToken(alumniToken),
      (err: any) => err instanceof OidcAuthError && err.code === "ineligible_role" && err.status === 403
    );

    // 7.10 Unverified email rejection when required
    const strictEmailOidc = new OidcService({
      issuerUrl: "https://identity.university.edu/v2.0",
      clientId: "incognito-institutional-app-id",
      allowedEmailDomains: ["university.edu"],
      requireEmailVerified: true,
    });
    const unverifiedEmailToken = strictEmailOidc.signToken({
      ...validOidcPayload,
      email_verified: false,
    });
    await assert.rejects(
      async () => strictEmailOidc.verifyInstitutionalToken(unverifiedEmailToken),
      (err: any) => err instanceof OidcAuthError && err.code === "unverified_email" && err.status === 403
    );

    // 7.11 Generic public error messages: NO internal details leaked
    try {
      await oidcTestService.verifyInstitutionalToken(wrongIssToken);
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.strictEqual(err.message, "Institutional token issuer is not recognized.");
      assert.ok(!err.message.includes("https://identity.university.edu"));
    }

    try {
      await oidcTestService.verifyInstitutionalToken(wrongAudToken);
      assert.fail("Should have thrown");
    } catch (err: any) {
      assert.strictEqual(err.message, "Institutional token audience is not valid for this application.");
      assert.ok(!err.message.includes("incognito-institutional-app-id"));
    }

    // 7.12 Pseudonym secret changes modify the derived pseudonym hash
    const serviceSecretA = new OidcService({
      issuerUrl: "https://identity.university.edu/v2.0",
      clientId: "incognito-institutional-app-id",
      allowedEmailDomains: ["university.edu"],
      pseudonymSecret: "super-secret-institution-salt-alpha-32chars!",
    });
    const serviceSecretB = new OidcService({
      issuerUrl: "https://identity.university.edu/v2.0",
      clientId: "incognito-institutional-app-id",
      allowedEmailDomains: ["university.edu"],
      pseudonymSecret: "super-secret-institution-salt-bravo-32chars!",
    });

    const tokenA = serviceSecretA.signToken(validOidcPayload);
    const tokenB = serviceSecretB.signToken(validOidcPayload);
    const resA = await serviceSecretA.verifyInstitutionalToken(tokenA);
    const resB = await serviceSecretB.verifyInstitutionalToken(tokenB);
    assert.notStrictEqual(resA.eligibilityProofHash, resB.eligibilityProofHash, "Different pseudonym secrets must derive different pseudonym hashes");
    assert.strictEqual(resA.institutionDomain, resB.institutionDomain);

    // 7.13 Missing pseudonym secret in deployed environment fails closed
    const origEnv = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = "production";
      assert.throws(
        () => new OidcService({
          issuerUrl: "https://identity.university.edu/v2.0",
          clientId: "incognito-institutional-app-id",
          pseudonymSecret: "",
        }),
        /FATAL: Deployed environment requires PSEUDONYM_SECRET/
      );
    } finally {
      process.env.NODE_ENV = origEnv;
    }

    // 7.14 Dynamic discovery issuer mismatch fails safely
    const discoveryServer = http.createServer((req, res) => {
      if (req.url === "/.well-known/openid-configuration") {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({
          issuer: "https://attacker-spoofed-issuer.com",
          jwks_uri: "http://127.0.0.1:9999/jwks",
        }));
      } else {
        res.writeHead(404);
        res.end();
      }
    });

    await new Promise<void>((resolve) => discoveryServer.listen(0, resolve));
    const discoveryPort = (discoveryServer.address() as any).port;
    const discoveryBaseUrl = `http://127.0.0.1:${discoveryPort}`;

    try {
      const discoveryOidc = new OidcService({
        issuerUrl: discoveryBaseUrl,
        clientId: "test-client",
        allowedEmailDomains: ["university.edu"],
        enableDiscovery: true,
      });

      await assert.rejects(
        async () => discoveryOidc.verifyInstitutionalToken(validToken),
        (err: any) => err instanceof OidcAuthError && err.code === "discovery_issuer_mismatch" && err.status === 503
      );
    } finally {
      discoveryServer.close();
    }
  });

  // =========================================================================
  // SECTION 4: REAL HTTP ENDPOINT & ENROLLMENT INTEGRATION TESTS
  // =========================================================================
  await suite.test("8. End-to-End OIDC Verification & Enrollment Route Integration", async () => {
    const app = createApp();

    await withServer(app, async (baseUrl) => {
      // 8.1 Call POST /api/auth/oidc/verify with institutional ID token
      const uniqueSub = `student-integration-${crypto.randomUUID()}`;
      const oidcPayload = {
        sub: uniqueSub,
        email: "whistleblower@university.edu",
        aud: "incognito-institutional-app-id",
        iss: "https://login.microsoftonline.com/institutional-tenant/v2.0",
        exp: Math.floor(Date.now() / 1000) + 3600,
        roles: ["Student"],
      };
      const institutionalIdToken = oidcService.signToken(oidcPayload);

      const verifyRes = await fetch(`${baseUrl}/api/auth/oidc/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: institutionalIdToken }),
      });
      assert.strictEqual(verifyRes.status, 200);
      const verifyData = await verifyRes.json() as any;
      assert.strictEqual(verifyData.eligible, true);
      assert.strictEqual(verifyData.institutionDomain, "university.edu");
      assert.strictEqual(verifyData.role, "student");
      assert.ok(verifyData.sessionToken, "Must return authenticated session token");

      // 8.2 Use issued sessionToken to query membership status
      const statusRes = await fetch(`${baseUrl}/api/membership/status`, {
        headers: { Authorization: `Bearer ${verifyData.sessionToken}` },
      });
      assert.strictEqual(statusRes.status, 200);

      // 8.3 Directly enroll with institutional ID token in POST /membership/enroll
      const clientIdentity = new Identity();
      const clientCommitment = clientIdentity.commitment.toString();
      const enrollRes = await fetch(`${baseUrl}/api/membership/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          idToken: institutionalIdToken,
          commitment: clientCommitment,
        }),
      });
      assert.strictEqual(enrollRes.status, 201, "Enrollment with genuine OIDC token must succeed with 201");
      const enrollData = await enrollRes.json() as any;
      assert.strictEqual(enrollData.membership?.status, "active");
      assert.strictEqual(enrollData.credential?.status, "registered");
      assert.strictEqual(enrollData.credential?.commitment, clientCommitment);

      // 8.4 Enrolled user queries credential status with session token
      const credRes = await fetch(`${baseUrl}/api/credential/status`, {
        headers: { Authorization: `Bearer ${verifyData.sessionToken}` },
      });
      assert.strictEqual(credRes.status, 200);
      const credData = await credRes.json() as any;
      assert.strictEqual(credData.state, "active");
      assert.strictEqual(credData.registered, true);

      // 8.5 Report submission uses anonymous ZK proof - NEVER transmits student identity or OIDC token
      const categoryId = "cat-harassment";
      const reportText = "Misconduct reported under hardened OIDC architecture.";
      const zkProof = await zkProofService.generateProof({
        identity: clientIdentity,
        topicScope: categoryId,
        reportBody: reportText,
      });

      const reportRes = await fetch(`${baseUrl}/api/reports`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          categoryId,
          body: reportText,
          proof: zkProof,
        }),
      });
      assert.strictEqual(reportRes.status, 201);
      const reportData = await reportRes.json() as any;
      assert.ok(reportData.reference.startsWith("INC-"));
      assert.ok(reportData.statusSecret.startsWith("sec_"));

      // 8.6 Verify identity lookup is architecturally forbidden
      const identityLookupRes = await fetch(`${baseUrl}/api/reports/${reportData.id}/identity`);
      assert.strictEqual(identityLookupRes.status, 403, "Identity lookup must be strictly prohibited with 403");

      // 8.7 Enrollment without client commitment fails with 400 invalid_commitment
      const noCommitmentRes = await fetch(`${baseUrl}/api/membership/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: institutionalIdToken }),
      });
      assert.strictEqual(noCommitmentRes.status, 400);
      const noCommitmentData = await noCommitmentRes.json() as any;
      assert.strictEqual(noCommitmentData.error, "invalid_commitment");

      // 8.8 Enrollment with malformed / non-scalar commitment fails with 400
      const malformedCommitmentRes = await fetch(`${baseUrl}/api/membership/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          idToken: institutionalIdToken,
          commitment: "not-a-valid-commitment-scalar",
        }),
      });
      assert.strictEqual(malformedCommitmentRes.status, 400);
      const malformedCommitmentData = await malformedCommitmentRes.json() as any;
      assert.strictEqual(malformedCommitmentData.error, "invalid_commitment");

      // 8.9 Enrollment with scalar exceeding SNARK_SCALAR_FIELD fails with 400
      const outOfBoundsScalar = "21888242871839275222246405745257275088548364400416034343698204186575808495618";
      const outOfBoundsRes = await fetch(`${baseUrl}/api/membership/enroll`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          idToken: institutionalIdToken,
          commitment: outOfBoundsScalar,
        }),
      });
      assert.strictEqual(outOfBoundsRes.status, 400);

      // 8.10 Enrollment response NEVER contains identitySecretExport
      assert.strictEqual(enrollData.credential?.identitySecretExport, undefined);
      assert.ok(!JSON.stringify(enrollData).includes("identitySecretExport"));

      // 8.11 OIDC verification with ineligible role returns 403
      const guestIdToken = oidcService.signToken({
        ...oidcPayload,
        sub: `guest-${crypto.randomUUID()}`,
        roles: ["Guest"],
      });
      const guestVerifyRes = await fetch(`${baseUrl}/api/auth/oidc/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: guestIdToken }),
      });
      assert.strictEqual(guestVerifyRes.status, 403);
      const guestVerifyData = await guestVerifyRes.json() as any;
      assert.strictEqual(guestVerifyData.error, "ineligible_role");

      // 8.12 OIDC verification with unauthorized domain returns 403
      const foreignIdToken = oidcService.signToken({
        ...oidcPayload,
        sub: `foreign-${crypto.randomUUID()}`,
        email: "attacker@unauthorized-external-campus.com",
      });
      const foreignVerifyRes = await fetch(`${baseUrl}/api/auth/oidc/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ idToken: foreignIdToken }),
      });
      assert.strictEqual(foreignVerifyRes.status, 403);
      const foreignVerifyData = await foreignVerifyRes.json() as any;
      assert.strictEqual(foreignVerifyData.error, "unauthorized_domain");
    });
  });
});
