import { describe, expect, it, vi } from "vitest";
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
      actor: await harness.actorFor(user.id),
      name: "CI",
    });

    expect(apiKey.plaintext).toMatch(/^key_[A-Za-z0-9_-]+$/);
    expect(apiKey.tokenHint).toBe(apiKey.plaintext.slice(-4));

    const state = await harness.me({
      useJar: false,
      headers: { Authorization: `Bearer ${apiKey.plaintext}` },
    });

    expect(state.authenticated).toBe(true);
    expect(state.credentialType).toBe("apiKey");
    expect(state.source).toBe("api");
    expect(state.actor).toEqual({
      type: "user",
      id: user.id,
      kind: "human",
      credentialId: apiKey.id,
      actionSource: "api",
    });
    expect(state.user?.id).toBe(user.id);
    expect(state.organization?.id).toBe(organizationId);
    expect(state.role).toBe("owner");
  });

  it("derives the action source from the client header", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "cli@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
      name: "CLI",
    });

    for (const [header, expected] of [
      ["cli", "cli"],
      ["mcp", "mcp"],
      ["something-else", "api"],
    ] as const) {
      const state = await harness.me({
        useJar: false,
        headers: {
          Authorization: `Bearer ${apiKey.plaintext}`,
          "X-Client": header,
        },
      });

      expect(state.source).toBe(expected);
    }
  });

  it("stores only a hash of the token", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "hash@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
      name: "Hashed",
    });

    const found = await harness.client.execute({
      sql: "SELECT token_hash, token_hint FROM api_key WHERE id = ?",
      args: [apiKey.id],
    });
    expect(found.rows[0]?.token_hash).toBe(await hashApiKeyToken(apiKey.plaintext));
    expect(found.rows[0]?.token_hint).toBe(apiKey.plaintext.slice(-4));
    expect(JSON.stringify(found.rows)).not.toContain(apiKey.plaintext);

    const listed = await harness.cfAuth.service.listApiKeys({
      organizationId,
      actor: await harness.actorFor(user.id),
    });
    expect(listed[0]?.tokenHint).toBe(apiKey.plaintext.slice(-4));
    expect(JSON.stringify(listed)).not.toContain(apiKey.plaintext);
  });

  it("rejects unknown and revoked tokens", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "revoke@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
      name: "Doomed",
    });

    expect(
      (
        await harness.me({
          useJar: false,
          headers: { Authorization: "Bearer key_nope" },
        })
      ).authenticated,
    ).toBe(false);

    const revoked = await harness.cfAuth.service.revokeApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
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
          actor: await harness.actorFor(user.id),
          apiKeyId: apiKey.id,
        })
      )?.revokedAt,
    ).toBe(revoked?.revokedAt);
  });

  it("verifies without writing to the key row", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "read-only@example.com");
    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
      name: "Read only verification",
    });
    await harness.client.execute(`CREATE TRIGGER reject_api_key_update
      BEFORE UPDATE ON api_key BEGIN SELECT RAISE(ABORT, 'verification wrote key'); END`);

    expect(
      (await harness.cfAuth.service.resolveApiKeyAuthState(apiKey.plaintext)).authenticated,
    ).toBe(true);
  });

  it("rejects a key at its exact expiry boundary and retains the row", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "expiry@example.com");
    const boundary = new Date("2030-01-02T03:04:05.000Z");
    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
      name: "Expiring",
      expiresAt: boundary,
    });

    vi.useFakeTimers();
    vi.setSystemTime(boundary);
    try {
      expect(
        (await harness.cfAuth.service.resolveApiKeyAuthState(apiKey.plaintext)).authenticated,
      ).toBe(false);
    } finally {
      vi.useRealTimers();
    }
    expect(
      (await harness.client.execute({ sql: "SELECT id FROM api_key WHERE id=?", args: [apiKey.id] }))
        .rows,
    ).toHaveLength(1);
  });

  it("emits api_key lifecycle events", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "events-key@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
      name: "Audited",
    });
    await harness.cfAuth.service.revokeApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
      apiKeyId: apiKey.id,
    });

    const types = harness.events.map((event) => event.type);
    expect(types).toContain("api_key.created");
    expect(types).toContain("api_key.revoked");
  });

  it("uses the configured token prefix", async () => {
    const harness = await createTestAuth({
      apiKeys: { enabled: true, tokenPrefix: "sk_live_" },
    });
    const { user, organizationId } = await signUpOwner(harness, "prefix-key@example.com");

    const apiKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(user.id),
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
        actor: await offHarness.actorFor(user.id),
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
      harness.cfAuth.service.createApiKey({
        organizationId,
        actor: await harness.actorFor(user.id),
        name: "  ",
      }),
    ).rejects.toMatchObject({ code: "validation_error", status: 422 });
  });

  it("rejects invalid and non-future expiry dates", async () => {
    const harness = await createTestAuth();
    const { user, organizationId } = await signUpOwner(harness, "bad-expiry@example.com");
    const actor = await harness.actorFor(user.id);
    for (const expiresAt of [new Date(Number.NaN), new Date(Date.now())]) {
      await expect(
        harness.cfAuth.service.createApiKey({ organizationId, actor, name: "Invalid", expiresAt }),
      ).rejects.toMatchObject({ code: "validation_error", status: 422 });
    }
  });
});
