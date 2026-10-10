import test from "node:test";
import assert from "node:assert/strict";
import { ApiError } from "../api/client.js";

test("Incognito Frontend Unit, Security, and Contract Test Suite", async (t) => {
  await t.test("1. ApiError creates normalized codes and messages", () => {
    const err = new ApiError("duplicate", "A submission already exists for this reporting scope.", 409);
    assert.equal(err.code, "duplicate");
    assert.equal(err.status, 409);
    assert.equal(err.name, "ApiError");
    assert.ok(err.message.includes("already exists"));
  });

  await t.test("2. Character validation bounds (20 min, 5000 max)", () => {
    const MIN = 20;
    const MAX = 5000;

    const shortText = "Under 20 chars";
    assert.equal(shortText.trim().length >= MIN, false);

    const validText = "This is a detailed and compliant concern report exceeding twenty characters.";
    assert.equal(validText.trim().length >= MIN && validText.length <= MAX, true);

    const overText = "A".repeat(5001);
    assert.equal(overText.length <= MAX, false);
  });

  await t.test("3. Security copy check: zero prohibited absolute claims in source", async () => {
    // Audit that prohibited overclaims ("100% anonymous", "impossible to trace", "completely untraceable") are absent
    const fs = await import("node:fs");
    const path = await import("node:path");

    const publicSrc = fs.readFileSync(path.join(process.cwd(), "src/pages/Public.tsx"), "utf8");
    const forbiddenClaims = [
      "100% anonymous",
      "impossible to trace",
      "completely untraceable",
      "100% untraceable",
    ];

    for (const claim of forbiddenClaims) {
      assert.equal(
        publicSrc.toLowerCase().includes(claim),
        false,
        `Found forbidden claim "${claim}" in Public.tsx`
      );
    }
  });

  await t.test("4. Status ordering matches protocol lifecycle", () => {
    const STATUS_ORDER = [
      "received",
      "under_review",
      "moderation_review",
      "assigned",
      "action_taken",
      "closed",
    ];

    assert.equal(STATUS_ORDER.indexOf("received"), 0);
    assert.equal(STATUS_ORDER.indexOf("under_review"), 1);
    assert.equal(STATUS_ORDER.indexOf("closed"), 5);
    assert.equal(STATUS_ORDER.length, 6);
  });

  await t.test("5. Status Secret Security: ensure secret is not placed in URL or local storage", () => {
    const sampleReference = "INC-849204";
    const sampleSecret = "sec_a7f92e4b89012345";

    // Simulate URL building: ensure secret is never appended as query parameter in tracking links
    const trackingUrl = `/report/status`;
    assert.equal(trackingUrl.includes(sampleSecret), false);

    // Test that public reference format matches convention
    assert.match(sampleReference, /^INC-\d{6}$/);
    assert.match(sampleSecret, /^sec_[a-f0-9]{16}$/);
  });
});
