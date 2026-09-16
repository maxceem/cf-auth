import { describe, expect, it } from "vitest";
import { deriveSecret, generateApiKeyToken, hashApiKeyToken } from "../src/crypto.js";
import { createTestAuth } from "./helpers.js";

describe("api key token generation", () => {
  it("produces distinct tokens of the requested shape with matching hashes and hints", async () => {
    const tokens = await Promise.all(
      Array.from({ length: 100 }, () => generateApiKeyToken("sk_live_")),
    );
    expect(new Set(tokens.map((token) => token.plaintext)).size).toBe(100);
    for (const token of tokens) {
      expect(token.plaintext).toMatch(/^sk_live_[A-Za-z0-9]{48}$/);
      expect(token.tokenHash).toBe(await hashApiKeyToken(token.plaintext));
      expect(token.tokenHint).toBe(token.plaintext.slice(-4));
    }
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
    await harness.signUp({
      email: "derived@example.com",
      password: "correct-horse-battery",
    });
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
    const harness = await createTestAuth({
      cookieSecret: "explicit-cookie-secret-value-0000",
    });

    expect(harness.cfAuth.config.cookieSecret).toBe("explicit-cookie-secret-value-0000");

    await harness.signUp({
      email: "explicit@example.com",
      password: "correct-horse-battery",
    });
    const state = await harness.me();

    // Round-trips end to end with the override in place.
    expect(state.organization).not.toBeNull();
    expect(harness.jar.has(harness.cfAuth.currentOrganizationCookie.name)).toBe(true);
  });
});
