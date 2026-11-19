import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { createTestAuth, type TestAuth } from "./helpers.js";

/** An organization a machine identity provisioned, with a key of its own. */
const serviceAccount = async (harness: TestAuth) => {
  const identity = await harness.cfAuth.service.createServiceIdentity({ name: "CLI service" });
  const membership = await harness.cfAuth.service.createOrganization(identity.id, "My account");
  const credential = await harness.cfAuth.service.issueServiceApiKey({
    userId: identity.id,
    organizationId: membership.organization.id,
    name: "CLI bootstrap",
  });
  return { identity, organizationId: membership.organization.id, credential };
};

describe("session evidence", () => {
  it("resolves nothing for a session id no session backs", async () => {
    const harness = await createTestAuth();
    await harness.sessions.human();

    expect(await harness.cfAuth.service.getAuthState("not-a-session", null)).toBeNull();
  });

  it("resolves nothing once the session has expired", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();
    const { session } = harness.cfAuth.config.tables;
    await harness.db
      .update(session)
      .set({ expiresAt: new Date(Date.now() - 1000) })
      .where(eq(session.id, human.sessionId));

    expect(await harness.cfAuth.service.getAuthState(human.sessionId, null)).toBeNull();
  });

  it("names the session that backs the state as the actor's credential", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();

    const state = await harness.cfAuth.service.getAuthState(human.sessionId, null);

    expect(state?.actor).toMatchObject({
      id: human.userId,
      credentialId: human.sessionId,
      actionSource: "web",
    });
  });

  it("refuses an API key where an interactive session is required", async () => {
    const harness = await createTestAuth();
    const account = await serviceAccount(harness);
    const actor = await harness.cfAuth.service.resolveApiKeyAuthState(
      account.credential.plaintext,
      "cli",
    );

    await expect(harness.cfAuth.service.listOrganizations(actor)).rejects.toMatchObject({
      code: "session_required",
    });
    await expect(
      harness.cfAuth.service.selectOrganization(actor, account.organizationId),
    ).rejects.toMatchObject({ code: "session_required" });
  });
});

describe("service API key activation", () => {
  it("reports a key issued disabled, and enables it once", async () => {
    const harness = await createTestAuth();
    const identity = await harness.cfAuth.service.createServiceIdentity({ name: "Build" });
    const membership = await harness.cfAuth.service.createOrganization(identity.id, "Automation");
    const key = await harness.cfAuth.service.issueServiceApiKey({
      userId: identity.id,
      organizationId: membership.organization.id,
      name: "Deferred",
      enabled: false,
    });

    expect(key.enabled).toBe(false);
    const [listed] = await harness.cfAuth.repository.listApiKeys(membership.organization.id);
    expect(listed).toMatchObject({ id: key.id, enabled: false });
    expect(
      (await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext, "cli")).authenticated,
    ).toBe(false);

    const enabled = await harness.cfAuth.service.enableServiceApiKey({
      apiKeyId: key.id,
      organizationId: membership.organization.id,
    });

    expect(enabled?.enabled).toBe(true);
    expect(
      (await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext, "cli")).authenticated,
    ).toBe(true);
  });

  it("will not bring a revoked key back", async () => {
    const harness = await createTestAuth();
    const account = await serviceAccount(harness);
    await harness.cfAuth.service.revokeServiceApiKey({
      apiKeyId: account.credential.id,
      organizationId: account.organizationId,
    });

    const enabled = await harness.cfAuth.service.enableServiceApiKey({
      apiKeyId: account.credential.id,
      organizationId: account.organizationId,
    });

    expect(enabled).toMatchObject({ enabled: false });
    expect(enabled?.revokedAt).not.toBeNull();
  });

  it("refuses to touch a key that belongs to a person", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();
    const key = await harness.cfAuth.service.createApiKey({
      actor: await harness.actorFor(human.userId, human.organizationId),
      organizationId: human.organizationId,
      name: "Personal",
    });

    await expect(
      harness.cfAuth.service.enableServiceApiKey({
        apiKeyId: key.id,
        organizationId: human.organizationId,
      }),
    ).rejects.toMatchObject({ code: "validation_error" });
  });
});
