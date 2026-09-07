import { describe, expect, it } from "vitest";
import { deriveSecret, generateApiKeyToken, hashApiKeyToken } from "../src/crypto.js";
import { createTestAuth } from "./helpers.js";

const base62 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

describe("api key token generation", () => {
  it("produces tokens of the requested shape", async () => {
    const token = await generateApiKeyToken("sk_live_", 48);

    expect(token.plaintext).toMatch(/^sk_live_[A-Za-z0-9]{48}$/);
    expect(token.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(token.tokenHash).toBe(await hashApiKeyToken(token.plaintext));
    expect(token.tokenHash).not.toContain(token.plaintext);
  });

  it("never emits a character outside the alphabet", async () => {
    for (let index = 0; index < 50; index += 1) {
      const { plaintext } = await generateApiKeyToken("k_", 64);

      for (const character of plaintext.slice(2)) {
        expect(base62).toContain(character);
      }
    }
  });

  it("is free of modulo bias", async () => {
    // With `byte % 62`, the first 8 characters of the alphabet would appear
    // ~5/4 as often as the rest. Sample enough to make that gap unmistakable.
    const counts = new Map<string, number>();
    let total = 0;

    for (let index = 0; index < 200; index += 1) {
      const { plaintext } = await generateApiKeyToken("", 256);

      for (const character of plaintext) {
        counts.set(character, (counts.get(character) ?? 0) + 1);
        total += 1;
      }
    }

    const expected = total / base62.length;
    const biasProne = base62.slice(0, 8);

    const biasProneAverage =
      [...biasProne].reduce((sum, character) => sum + (counts.get(character) ?? 0), 0) /
      biasProne.length;
    const restAverage =
      [...base62.slice(8)].reduce((sum, character) => sum + (counts.get(character) ?? 0), 0) /
      (base62.length - 8);

    // A biased generator lands near 1.25; a uniform one near 1.0.
    expect(biasProneAverage / restAverage).toBeLessThan(1.1);
    expect(biasProneAverage / expected).toBeLessThan(1.1);
  });

  it("generates distinct tokens", async () => {
    const tokens = await Promise.all(
      Array.from({ length: 100 }, () => generateApiKeyToken("k_", 32)),
    );

    expect(new Set(tokens.map((token) => token.plaintext)).size).toBe(100);
  });
});

describe("secret derivation", () => {
  it("is deterministic, domain-separated and not the input secret", async () => {
    const secret = "master-secret-value-for-tests-000000";

    const a = await deriveSecret(secret, "cf-auth:one");
    const b = await deriveSecret(secret, "cf-auth:one");
    const c = await deriveSecret(secret, "cf-auth:two");

    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(a).not.toBe(secret);
    expect(a).toMatch(/^[0-9a-f]{64}$/);
  });

  it("does not sign the org cookie with the raw better-auth secret", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "derived@example.com", password: "correct-horse-battery" });
    await harness.me();

    const cookieName = harness.cfAuth.currentOrganizationCookie.name;
    const value = harness.jar.get(cookieName);
    expect(value).toBeDefined();

    // A cookie helper keyed directly on the master secret must NOT verify it.
    const { createCurrentOrganizationCookie } = await import("../src/cookies.js");
    const { resolveConfig } = await import("../src/config.js");
    const { Hono } = await import("hono");

    const rawKeyed = createCurrentOrganizationCookie(
      resolveConfig({
        appName: harness.cfAuth.config.appName,
        secret: harness.cfAuth.config.secret,
        cookieSecret: harness.cfAuth.config.secret, // explicit == the master secret
        db: {} as never,
      }),
    );

    const app = new Hono();
    app.get("/read", async (c) => c.json({ value: await rawKeyed.read(c) }));

    const response = await app.request("http://localhost/read", {
      headers: { Cookie: `${rawKeyed.name}=${value}` },
    });

    expect(await response.json()).toEqual({ value: null });
  });

  it("honours an explicit cookieSecret override", async () => {
    const harness = await createTestAuth({ cookieSecret: "explicit-cookie-secret-value-0000" });

    expect(harness.cfAuth.config.cookieSecret).toBe("explicit-cookie-secret-value-0000");

    await harness.signUp({ email: "explicit@example.com", password: "correct-horse-battery" });
    const state = await harness.me();

    // Round-trips end to end with the override in place.
    expect(state.organization).not.toBeNull();
    expect(harness.jar.has(harness.cfAuth.currentOrganizationCookie.name)).toBe(true);
  });
});
