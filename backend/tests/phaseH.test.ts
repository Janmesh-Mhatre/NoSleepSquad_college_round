import test from "node:test";
import assert from "node:assert/strict";
import { GeminiModerationProvider } from "../moderation/providers/gemini.js";
import { OpenAIModerationProvider } from "../moderation/providers/openai.js";
import { BlockchainAuditAdapter } from "../services/blockchainService.js";
import { oidcService, OidcAuthError } from "../services/oidcService.js";
import { ProductionKMSProvider, DevelopmentKeyProvider } from "../services/keyService.js";
import { metricsService } from "../services/metricsService.js";

test("PHASE H — External API Integration & Resilient Architecture", async (t) => {
  await t.test("H1. AI APIs: Gemini and OpenAI providers enforce backend-only authentication & minimal data", async () => {
    // 1. Missing keys throw explicit configuration errors, never leaking frontend secrets
    const gemini = new GeminiModerationProvider({ apiKey: "" });
    await assert.rejects(
      async () => gemini.moderate("Test report body", "cat-academic"),
      /GEMINI_CONFIG_ERROR/
    );

    const openai = new OpenAIModerationProvider({ apiKey: "" });
    await assert.rejects(
      async () => openai.moderate("Test report body", "cat-academic"),
      /OPENAI_CONFIG_ERROR/
    );
  });

  await t.test("H2. Blockchain RPC: Multi-RPC failover switches from primary to backup RPC", () => {
    const primaryRpc = "https://eth-sepolia.g.alchemy.com/v2/demo-key";
    const backupRpc = "https://sepolia.infura.io/v3/demo-backup-key";

    const adapter = new BlockchainAuditAdapter({
      rpcUrl: primaryRpc,
      backupRpcUrl: backupRpc,
      contractAddress: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
    });

    assert.strictEqual(adapter.getActiveRpcUrl(), primaryRpc);

    // Trigger failover to secondary backup
    const failedOver = adapter.failoverToBackup();
    assert.strictEqual(failedOver, true);
    assert.strictEqual(adapter.getActiveRpcUrl(), backupRpc);
  });

  await t.test("H3. Institutional OIDC: Validates institutional domain & audience without PII leakage", async () => {
    // 1. Valid institutional token from authorized domain with genuine cryptographic signature
    const validPayload = {
      sub: "student-sub-994821",
      email: "whistleblower@university.edu",
      aud: "incognito-institutional-app-id",
      iss: "https://login.microsoftonline.com/institutional-tenant/v2.0",
      exp: Math.floor(Date.now() / 1000) + 3600,
      roles: ["Student"],
    };
    const validToken = oidcService.signToken(validPayload);

    const identity = await oidcService.verifyInstitutionalToken(validToken);
    assert.strictEqual(identity.eligible, true);
    assert.strictEqual(identity.institutionDomain, "university.edu");
    assert.strictEqual(identity.role, "student");
    assert.ok(identity.eligibilityProofHash, "Pseudonymous proof hash must be generated");

    // 2. Algorithm 'none' attack is strictly rejected
    const noneToken = `eyJhbGciOiJub25lIn0.${Buffer.from(JSON.stringify(validPayload)).toString("base64url")}.invalidsig`;
    await assert.rejects(
      async () => oidcService.verifyInstitutionalToken(noneToken),
      (err: any) => err instanceof OidcAuthError && err.code === "unsupported_algorithm"
    );

    // 3. Cryptographic signature tampering is strictly rejected
    const tamperedSigToken = validToken.substring(0, validToken.length - 4) + "abcd";
    await assert.rejects(
      async () => oidcService.verifyInstitutionalToken(tamperedSigToken),
      (err: any) => err instanceof OidcAuthError && err.code === "invalid_signature"
    );

    // 4. Unauthorized email domain rejected
    const foreignPayload = {
      ...validPayload,
      email: "attacker@gmail.com",
    };
    const foreignToken = oidcService.signToken(foreignPayload);

    await assert.rejects(
      async () => oidcService.verifyInstitutionalToken(foreignToken),
      (err: any) => err instanceof OidcAuthError && err.code === "unauthorized_domain"
    );

    // 5. Expired token rejected
    const expiredPayload = {
      ...validPayload,
      exp: Math.floor(Date.now() / 1000) - 300,
    };
    const expiredToken = oidcService.signToken(expiredPayload);

    await assert.rejects(
      async () => oidcService.verifyInstitutionalToken(expiredToken),
      (err: any) => err instanceof OidcAuthError && err.code === "token_expired"
    );

    // 6. Audience mismatch rejected
    const wrongAudPayload = {
      ...validPayload,
      aud: "wrong-audience-id",
    };
    const wrongAudToken = oidcService.signToken(wrongAudPayload);

    await assert.rejects(
      async () => oidcService.verifyInstitutionalToken(wrongAudToken),
      (err: any) => err instanceof OidcAuthError && err.code === "invalid_audience"
    );
  });

  await t.test("H4. Production Key Management: KMS provider fails closed if insecure key provided", () => {
    // Development key provider allows local fallback
    const devProvider = new DevelopmentKeyProvider("local-dev-seed");
    assert.ok(devProvider.getKey() instanceof Buffer);

    // Production KMS provider strictly throws on weak, dev, or default keys
    assert.throws(
      () => new ProductionKMSProvider("dev-only-local-encryption-key-32b!"),
      /FATAL: Production environment requires a securely injected ENCRYPTION_KEY/
    );

    assert.throws(
      () => new ProductionKMSProvider("short-key"),
      /FATAL/
    );

    // Valid 32-byte production key succeeds
    const prodProvider = new ProductionKMSProvider("super-secure-production-vault-kms-key-32bytes-min!");
    assert.strictEqual(prodProvider.getKey().length, 32);
  });

  await t.test("H5. API Observability: Operational metrics recorded with zero sensitive data", () => {
    metricsService.recordCall("gemini", 180);
    metricsService.recordCall("blockchainRpc", 420);
    metricsService.recordFailure("openai");
    metricsService.recordRetry();

    const snapshot = metricsService.getSnapshot();
    assert.ok(snapshot.totalRequests >= 2);
    assert.ok(snapshot.providerCalls.gemini >= 1);
    assert.ok(snapshot.failureCounts.openai >= 1);
    assert.ok(snapshot.retryCounts >= 1);
    assert.ok(snapshot.averageLatencyMs > 0);

    // Privacy assertion: zero PII or credentials in metrics
    assert.strictEqual(metricsService.assertMetricsPrivacy(), true);
  });
});
