import test from "node:test";
import assert from "node:assert/strict";
import { authService, JwtAuthProvider, MockAuthProvider, AuthError } from "../services/authService.js";
import { requireRole } from "../middleware/auth.js";
import { createApp } from "../app.js";

test("PHASE A — Security & RBAC Hardening Test Suite", async (t) => {
  const jwtProvider = new JwtAuthProvider("phase-a-test-secret-key-32-chars-long!");

  const memberToken = jwtProvider.generateToken({ sub: "student-101", role: "member" });
  const moderatorToken = jwtProvider.generateToken({ sub: "staff-mod-42", role: "moderator" });
  const adminToken = jwtProvider.generateToken({ sub: "chief-admin-01", role: "admin" });

  await t.test("A1. Valid cryptographic tokens parse claims correctly", () => {
    const claims = jwtProvider.verifyToken(moderatorToken);
    assert.equal(claims.sub, "staff-mod-42");
    assert.equal(claims.role, "moderator");
    assert.ok(claims.exp > Math.floor(Date.now() / 1000));
  });

  await t.test("A2. Removal of client-controlled authorization (X-Staff-Role ignored)", () => {
    const middleware = requireRole(["moderator", "admin"]);
    let statusCode = 200;
    let jsonBody: any = null;
    const mockRes: any = {
      status: (code: number) => {
        statusCode = code;
        return { json: (b: any) => { jsonBody = b; } };
      },
    };

    // Client sends X-Staff-Role: admin with NO valid token
    const mockReqForged: any = {
      headers: { "x-staff-role": "admin" },
    };
    let nextCalled = false;
    middleware(mockReqForged, mockRes, () => { nextCalled = true; });

    assert.equal(nextCalled, false, "Must not allow forged header");
    assert.equal(statusCode, 401, "Must require real Bearer token");
    assert.equal(jsonBody.error, "unauthenticated");
  });

  await t.test("A3. Moderator identity derived strictly from server-side token context", () => {
    // When a valid moderator token is used, req.user is set to claims
    const middleware = requireRole(["moderator", "admin"]);
    let nextCalled = false;
    const mockRes: any = {
      status: () => ({ json: () => {} }),
    };

    const mockReq: any = {
      headers: { authorization: `Bearer ${moderatorToken}` },
      body: { moderatorId: "forged-impostor-id" }, // Attempting client-side forgery
    };

    // Temporarily point authService to our test provider
    authService.setProvider(jwtProvider);

    middleware(mockReq, mockRes, () => { nextCalled = true; });

    assert.equal(nextCalled, true);
    assert.equal(mockReq.user.sub, "staff-mod-42", "Must preserve authenticated principal");
    assert.equal(mockReq.staffRole, "moderator");
  });

  await t.test("A4. Strict RBAC Enforcement (Member denied, Moderator allowed, Mod denied on Admin)", () => {
    const modMiddleware = requireRole(["moderator", "admin"]);
    const adminMiddleware = requireRole(["admin"]);

    let status = 200;
    let resBody: any = null;
    const mockRes: any = {
      status: (c: number) => { status = c; return { json: (b: any) => { resBody = b; } }; },
    };

    authService.setProvider(jwtProvider);

    // 1. Member accessing moderator endpoint -> 403 Forbidden
    let next = false;
    modMiddleware({ headers: { authorization: `Bearer ${memberToken}` } } as any, mockRes, () => { next = true; });
    assert.equal(next, false);
    assert.equal(status, 403);
    assert.equal(resBody.error, "unauthorized");

    // 2. Moderator accessing moderator endpoint -> 200 Allowed
    next = false;
    modMiddleware({ headers: { authorization: `Bearer ${moderatorToken}` } } as any, mockRes, () => { next = true; });
    assert.equal(next, true);

    // 3. Moderator accessing admin endpoint -> 403 Forbidden
    next = false;
    adminMiddleware({ headers: { authorization: `Bearer ${moderatorToken}` } } as any, mockRes, () => { next = true; });
    assert.equal(next, false);
    assert.equal(status, 403);

    // 4. Admin accessing admin endpoint -> 200 Allowed
    next = false;
    adminMiddleware({ headers: { authorization: `Bearer ${adminToken}` } } as any, mockRes, () => { next = true; });
    assert.equal(next, true);
  });

  await t.test("A5. Cryptographic signature tampering & invalid tokens rejected", () => {
    // Tamper with the signature
    const parts = moderatorToken.split(".");
    const tampered = `${parts[0]}.${parts[1]}.invalidsignature123`;

    assert.throws(
      () => jwtProvider.verifyToken(tampered),
      (err: any) => err instanceof AuthError && err.code === "invalid_signature"
    );

    // Malformed token
    assert.throws(
      () => jwtProvider.verifyToken("not.a.jwt.token"),
      (err: any) => err instanceof AuthError
    );
  });

  await t.test("A6. Expired token rejected", () => {
    // Generate token that expired 10 seconds ago
    const expiredToken = jwtProvider.generateToken({
      sub: "old-mod",
      role: "moderator",
      exp: Math.floor(Date.now() / 1000) - 10,
    });

    assert.throws(
      () => jwtProvider.verifyToken(expiredToken),
      (err: any) => err instanceof AuthError && err.code === "token_expired"
    );
  });

  await t.test("A7. Fail-Closed Mock Auth Provider in Production", () => {
    const originalEnv = process.env.NODE_ENV;
    try {
      process.env.NODE_ENV = "production";
      assert.throws(
        () => new MockAuthProvider(),
        /FATAL: MockAuthProvider is strictly prohibited in production/
      );
    } finally {
      process.env.NODE_ENV = originalEnv;
    }
  });

  await t.test("A8. Strict CORS Allowlist Rejects Unauthorized Origins", async () => {
    const app = createApp();

    // Verify app handles requests with rejected CORS origin
    const res = await new Promise<{ status: number; body: string }>((resolve) => {
      const server = app.listen(0, () => {
        const address = server.address() as any;
        const port = address.port;

        fetch(`http://127.0.0.1:${port}/api/health`, {
          headers: { Origin: "http://malicious-attacker-domain.evil" },
        })
          .then(async (r) => {
            const body = await r.text();
            server.close(() => resolve({ status: r.status, body }));
          })
          .catch((err) => {
            server.close(() => resolve({ status: 500, body: err.message }));
          });
      });
    });

    // In Express with CORS error, it responds with error or 500 without Access-Control-Allow-Origin
    assert.ok(res.status >= 400 || res.body.includes("CORS"), "Must reject or fail unauthorized origin");
  });

  await t.test("A9. Zero sensitive information leaked in authentication errors", () => {
    const middleware = requireRole(["moderator"]);
    let resBody: any = null;
    const mockRes: any = {
      status: () => ({ json: (b: any) => { resBody = b; } }),
    };

    middleware({ headers: { authorization: "Bearer invalid.jwt.here" } } as any, mockRes, () => {});
    assert.ok(!JSON.stringify(resBody).includes("secret"));
    assert.ok(!JSON.stringify(resBody).includes("key"));
    assert.ok(!JSON.stringify(resBody).includes("trace"));
  });
});
