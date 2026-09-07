import { describe, expect, it } from "vitest";
import { hashApiKeyToken } from "../src/crypto.js";
import { createTestAuth, type TestAuth } from "./helpers.js";

const signUpOwner = async (harness: TestAuth, email = "keys@example.com") => {
  harness.jar.clear();
  await harness.signUp({ email, password: "correct-horse-battery" });
  const user = await harness.cfAuth.repository.findUserByEmail(email);
  const [membership] = await harness.cfAuth.repository.listOrganizationsForUser(user!.id);
  return { user: user!, organizationId: membership!.organization.id };
};

describe("api key authentication", () => {
  it("authenticates a bearer token and scopes it to the issuing organization", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness);

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: user.id,
      name: "CI",
    });

    expect(apiKey.plaintext).toMatch(/^key_[A-Za-z0-9]{48}$/);
    expect(apiKey.tokenHint).toBe(apiKey.plaintext.slice(-4));

    const state = await harness.me({
      useJar: false,
      headers: { Authorization: `Bearer ${apiKey.plaintext}` },
    });

    expect(state.authenticated).toBe(true);
    expect(state.credentialType).toBe("apiKey");
    expect(state.source).toBe("api");
    expect(state.actor).toEqual({ type: "api_key", id: apiKey.id, actionSource: "api" });
    expect(state.user).toBeNull();
    expect(state.organization?.id).toBe(organizationId);
    expect(state.role).toBe("owner");
  });

  it("derives the action source from the client header", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "cli@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: user.id,
      name: "CLI",
    });

    for (const [header, expected] of [
      ["cli", "cli"],
      ["mcp", "mcp"],
      ["something-else", "api"],
    ] as const) {
      const state = await harness.me({
        useJar: false,
        headers: { Authorization: `Bearer ${apiKey.plaintext}`, "X-Client": header },
      });

      expect(state.source).toBe(expected);
    }
  });

  it("stores only a hash of the token", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "hash@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: user.id,
      name: "Hashed",
    });

    const found = await harness.cfAuth.repository.findActiveApiKeyByHash(
      await hashApiKeyToken(apiKey.plaintext),
    );

    expect(found?.id).toBe(apiKey.id);
    const listed = await harness.cfAuth.service.listApiKeys({ organizationId, actorUserId: user.id });
    expect(listed[0]?.tokenHint).toBe(apiKey.plaintext.slice(-4));
    expect(JSON.stringify(listed)).not.toContain(apiKey.plaintext);
  });

  it("rejects unknown and revoked tokens", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "revoke@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: user.id,
      name: "Doomed",
    });

    expect(
      (await harness.me({ useJar: false, headers: { Authorization: "Bearer key_nope" } }))
        .authenticated,
    ).toBe(false);

    const revoked = await harness.cfAuth.service.revokeApiKey({
      organizationId,
      actorUserId: user.id,
      apiKeyId: apiKey.id,
    });
    expect(revoked?.revokedAt).not.toBeNull();

    const state = await harness.me({
      useJar: false,
      headers: { Authorization: `Bearer ${apiKey.plaintext}` },
    });
    expect(state.authenticated).toBe(false);

    // Revoking twice is a no-op rather than an error.
    expect(
      (
        await harness.cfAuth.service.revokeApiKey({
          organizationId,
          actorUserId: user.id,
          apiKeyId: apiKey.id,
        })
      )?.revokedAt,
    ).toBe(revoked?.revokedAt);
  });

  it("emits api_key lifecycle events", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "events-key@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: user.id,
      name: "Audited",
    });
    await harness.cfAuth.service.revokeApiKey({
      organizationId,
      actorUserId: user.id,
      apiKeyId: apiKey.id,
    });

    const types = harness.events.map((event) => event.type);
    expect(types).toContain("api_key.created");
    expect(types).toContain("api_key.revoked");
  });

  it("uses the configured token prefix", async () => {
    const harness = await createTestAuth({ apiKeys: { enabled: true, tokenPrefix: "sk_live_" } });
    const { user, organizationId } = await signUpOwner(harness, "prefix-key@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: user.id,
      name: "Prefixed",
    });

    expect(apiKey.plaintext.startsWith("sk_live_")).toBe(true);
  });

  it("is opt-in and inert when disabled", async () => {
    // The package default is `apiKeys.enabled: false` (asserted in config.test.ts);
    // the shared harness turns it on, so build one with it explicitly off.
    const offHarness = await createTestAuth({ apiKeys: { enabled: false } });
    const { user, organizationId } = await signUpOwner(offHarness, "off@example.com");

    expect(offHarness.cfAuth.config.apiKeys.enabled).toBe(false);

    await expect(
      offHarness.cfAuth.service.createApiKey({
        organizationId,
        actorUserId: user.id,
        name: "Nope",
      }),
    ).rejects.toMatchObject({ code: "validation_error" });

    // A bearer header must not be treated as an API key when the feature is off.
    const state = await offHarness.me({
      useJar: false,
      headers: { Authorization: "Bearer key_whatever" },
    });
    expect(state.authenticated).toBe(false);
  });

  it("requires a non-empty key name", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "noname@example.com");

    await expect(
      harness.cfAuth.service.createApiKey({ organizationId, actorUserId: user.id, name: "  " }),
    ).rejects.toMatchObject({ code: "validation_error", status: 422 });
  });
});
