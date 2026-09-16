import { and, eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { requireOrganization, requireUser } from "../src/middleware.js";
import { createTestSessions } from "../src/testing.js";
import { createTestAuth } from "./helpers.js";

const serviceSetup = async () => {
  const harness = await createTestAuth();
  const identity = await harness.cfAuth.service.createServiceIdentity({
    name: "Build service",
  });
  const membership = await harness.cfAuth.service.createOrganization(identity.id, "Automation");
  const key = await harness.cfAuth.service.issueServiceApiKey({
    userId: identity.id,
    organizationId: membership.organization.id,
    name: "CLI",
  });
  return { ...harness, identity, membership, key };
};

describe("unified identities", () => {
  it("issues and verifies a custom key for an email-less service without login records or fake sessions", async () => {
    const harness = await serviceSetup();
    const state = await harness.cfAuth.service.resolveApiKeyAuthState(harness.key.plaintext, "cli");
    expect(state.user).toMatchObject({
      id: harness.identity.id,
      kind: "service",
      email: null,
    });
    expect(state).toMatchObject({
      role: "owner",
      assurance: "credential",
    });
    expect(state.actor).toMatchObject({
      id: harness.identity.id,
      credentialId: harness.key.id,
    });
    expect(state.organization).toMatchObject({
      claimed: false,
      expiresAt: null,
    });
    expect((await harness.client.execute("SELECT * FROM user_account")).rows).toHaveLength(0);
    expect((await harness.client.execute("SELECT * FROM user_session")).rows).toHaveLength(0);
    expect(() => requireUser(state)).toThrow();
    expect(() => requireOrganization(state, "owner")).not.toThrow();
    await expect(
      harness.cfAuth.service.createApiKey({
        actor: state,
        organizationId: harness.membership.organization.id,
        name: "Second automation key",
      }),
    ).resolves.toMatchObject({ userId: harness.identity.id });
    await expect(
      harness.cfAuth.service.addOrganizationMember({
        actor: state,
        organizationId: harness.membership.organization.id,
        userId: harness.identity.id,
        role: "owner",
      }),
    ).rejects.toMatchObject({ code: "already_a_member" });
  });

  it("rechecks current membership immediately", async () => {
    const harness = await serviceSetup();
    const tables = harness.cfAuth.config.tables;
    await harness.db
      .update(tables.organizationUser)
      .set({ role: "member" })
      .where(eq(tables.organizationUser.userId, harness.identity.id));
    expect((await harness.cfAuth.service.resolveApiKeyAuthState(harness.key.plaintext)).role).toBe(
      "member",
    );
    await harness.db
      .delete(tables.organizationUser)
      .where(eq(tables.organizationUser.userId, harness.identity.id));
    expect(
      (await harness.cfAuth.service.resolveApiKeyAuthState(harness.key.plaintext)).authenticated,
    ).toBe(false);
  });

  it("keeps a key restricted to its organization even when its identity owns another", async () => {
    const harness = await serviceSetup();
    const second = await harness.cfAuth.service.createOrganization(
      harness.identity.id,
      "Other automation account",
    );
    const state = await harness.cfAuth.service.resolveApiKeyAuthState(harness.key.plaintext);

    await expect(
      harness.cfAuth.service.createApiKey({
        actor: state,
        organizationId: second.organization.id,
        name: "Cross-account key",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      harness.cfAuth.service.listApiKeys({
        actor: state,
        organizationId: second.organization.id,
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      harness.cfAuth.service.addOrganizationMember({
        actor: state,
        organizationId: second.organization.id,
        userId: harness.identity.id,
        role: "member",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    await expect(
      harness.cfAuth.service.createApiKey({
        actor: state,
        organizationId: harness.membership.organization.id,
        name: "Same-account key",
      }),
    ).resolves.toMatchObject({ organizationId: harness.membership.organization.id });
  });

  it("does not give human keys interactive assurance or expose key management routes", async () => {
    const harness = await createTestAuth();
    const human = await createTestSessions(harness.cfAuth).human();
    const actor = await harness.actorFor(human.userId);
    const key = await harness.cfAuth.service.createApiKey({
      actor,
      organizationId: human.organizationId,
      name: "Human automation",
    });
    const state = await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext);
    expect(state.user?.kind).toBe("human");
    expect(() => requireUser(state)).toThrow();
    const response = await harness.request(`${harness.cfAuth.basePath}/api-key/create`, {
      json: { name: "bypass" },
      headers: { Cookie: human.cookie },
    });
    expect(response.status).toBe(404);
  });

  it("enforces key expiry and keeps a service owner from satisfying the last human owner guard", async () => {
    const harness = await serviceSetup();
    const human = await createTestSessions(harness.cfAuth).human();
    const tables = harness.cfAuth.config.tables;
    await harness.cfAuth.repository.addOrganizationUser({
      organizationId: human.organizationId,
      userId: harness.identity.id,
      role: "owner",
    });
    const actor = await harness.actorFor(human.userId, human.organizationId);
    await expect(
      harness.cfAuth.service.removeOrganizationMember({
        actor,
        organizationId: human.organizationId,
        userId: human.userId,
      }),
    ).rejects.toMatchObject({ code: "last_owner" });
    await harness.db
      .update(tables.apiKey)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(tables.apiKey.id, harness.key.id));
    expect(
      (await harness.cfAuth.service.resolveApiKeyAuthState(harness.key.plaintext)).authenticated,
    ).toBe(false);
    expect(await harness.cfAuth.repository.findUserById(harness.identity.id)).not.toBeNull();
    expect(
      await harness.db
        .select()
        .from(tables.organizationUser)
        .where(
          and(
            eq(tables.organizationUser.userId, human.userId),
            eq(tables.organizationUser.organizationId, human.organizationId),
          ),
        ),
    ).toHaveLength(1);
  });

});

for (const basePath of ["/", "/api/auth", "/custom/auth"]) {
  it(`blocks every public API key endpoint under ${basePath}`, async () => {
    const harness = await createTestAuth({ basePath });
    const prefix = basePath === "/" ? "" : basePath;
    for (const path of ["api-key/create", "%61pi-key/create", "api-key", "api-key/"]) {
      const response = await harness.cfAuth.handler(
        new Request(`http://localhost:8787${prefix}/${path}`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: "{}",
        }),
      );
      expect(response.status).toBe(404);
    }
  });
}

it("keeps an issued service credential inactive until its protected exchange commits", async () => {
  const harness = await serviceSetup();
  const inactive = await harness.cfAuth.service.issueServiceApiKey({ userId: harness.identity.id, organizationId: harness.membership.organization.id, name: "Protected exchange", enabled: false });
  expect((await harness.cfAuth.service.resolveApiKeyAuthState(inactive.plaintext)).authenticated).toBe(false);
  await harness.db.update(harness.cfAuth.config.tables.apiKey).set({ enabled: true }).where(eq(harness.cfAuth.config.tables.apiKey.id, inactive.id));
  expect((await harness.cfAuth.service.resolveApiKeyAuthState(inactive.plaintext)).user?.id).toBe(harness.identity.id);
});
