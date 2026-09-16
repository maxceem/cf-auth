import { eq } from "drizzle-orm";
import { describe, expect, it } from "vitest";
import { createTestAuth, type TestAuth } from "./helpers.js";

const past = () => new Date(Date.now() - 60_000).toISOString();
const future = () => new Date(Date.now() + 86_400_000).toISOString();

const setDeadline = async (harness: TestAuth, organizationId: string, expiresAt: string | null) => {
  const { organization } = harness.cfAuth.config.tables;
  await harness.db
    .update(organization)
    .set({ expiresAt })
    .where(eq(organization.id, organizationId));
};

/**
 * An organization provisioned by a machine identity and waiting for a person —
 * the shape a CLI bootstrap leaves behind.
 */
const unclaimedAccount = async (harness: TestAuth) => {
  const identity = await harness.cfAuth.service.createServiceIdentity({ name: "CLI service" });
  const membership = await harness.cfAuth.service.createOrganization(identity.id, "My account");
  await setDeadline(harness, membership.organization.id, future());
  const credential = await harness.cfAuth.service.issueServiceApiKey({
    userId: identity.id,
    organizationId: membership.organization.id,
    name: "CLI bootstrap",
  });
  return { identity, organizationId: membership.organization.id, credential };
};

describe("organization deadlines", () => {
  it("keeps a session out of an organization whose deadline has passed", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();
    await setDeadline(harness, human.organizationId, past());

    const state = await harness.actorFor(human.userId, human.organizationId);

    expect(state.organization).toBeNull();
    expect(state.role).toBeNull();
    // Still named, so a client can say which organization is unavailable.
    expect(state.memberships.map((membership) => membership.organization.id)).toEqual([
      human.organizationId,
    ]);
  });

  it("acts in a live organization rather than an expired current one", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();
    const second = await harness.cfAuth.service.createOrganization(human.userId, "Second");
    await setDeadline(harness, human.organizationId, past());

    const state = await harness.actorFor(human.userId, human.organizationId);

    expect(state.organization?.id).toBe(second.organization.id);
    expect(state.role).toBe("owner");
  });

  it("refuses to switch into an expired organization", async () => {
    const harness = await createTestAuth();
    const human = await harness.sessions.human();
    const second = await harness.cfAuth.service.createOrganization(human.userId, "Second");
    await setDeadline(harness, second.organization.id, past());

    await expect(
      harness.cfAuth.service.selectOrganization(
        await harness.actorFor(human.userId),
        second.organization.id,
      ),
    ).rejects.toMatchObject({ code: "organization_expired", status: 403 });
  });

  it("refuses an API key for an expired organization, as it always has", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    await setDeadline(harness, account.organizationId, past());

    const state = await harness.cfAuth.service.resolveApiKeyAuthState(
      account.credential.plaintext,
      "cli",
    );

    expect(state.authenticated).toBe(false);
  });
});

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
    const account = await unclaimedAccount(harness);
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
    await expect(
      harness.cfAuth.service.claimOrganization({
        actor,
        organizationId: account.organizationId,
      }),
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
    const account = await unclaimedAccount(harness);
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

  it("will not enable a key inside an expired organization", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    await harness.cfAuth.service.revokeServiceApiKey({
      apiKeyId: account.credential.id,
      organizationId: account.organizationId,
    });
    const waiting = await harness.cfAuth.service.issueServiceApiKey({
      userId: account.identity.id,
      organizationId: account.organizationId,
      name: "Later",
      enabled: false,
    });
    await setDeadline(harness, account.organizationId, past());

    const enabled = await harness.cfAuth.service.enableServiceApiKey({
      apiKeyId: waiting.id,
      organizationId: account.organizationId,
    });

    expect(enabled).toMatchObject({ enabled: false });
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

describe("claiming an organization", () => {
  it("hands the organization to a person and clears its deadline", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    const human = await harness.sessions.human();

    const membership = await harness.cfAuth.service.claimOrganization({
      actor: await harness.actorFor(human.userId),
      organizationId: account.organizationId,
      provisioning: {
        userId: account.identity.id,
        credentialId: account.credential.id,
        revokeAccess: false,
      },
    });

    expect(membership).toMatchObject({ role: "owner" });
    expect(membership.organization).toMatchObject({ claimed: true, expiresAt: null });
    expect(harness.events).toContainEqual({
      type: "organization.claimed",
      userId: human.userId,
      organizationId: account.organizationId,
    });
    // Ongoing access was allowed, so the CLI credential still authenticates.
    expect(
      (await harness.cfAuth.service.resolveApiKeyAuthState(account.credential.plaintext, "cli"))
        .authenticated,
    ).toBe(true);
  });

  it("retires the provisioning identity when ongoing access is declined", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    const human = await harness.sessions.human();

    await harness.cfAuth.service.claimOrganization({
      actor: await harness.actorFor(human.userId),
      organizationId: account.organizationId,
      provisioning: {
        userId: account.identity.id,
        credentialId: account.credential.id,
        revokeAccess: true,
      },
    });

    expect(
      (await harness.cfAuth.service.resolveApiKeyAuthState(account.credential.plaintext, "cli"))
        .authenticated,
    ).toBe(false);
    expect(
      await harness.cfAuth.repository.findMembership(
        account.identity.id,
        account.organizationId,
      ),
    ).toBeNull();
  });

  it("settles the same way when the claim is repeated", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    const human = await harness.sessions.human();
    const claim = async () =>
      harness.cfAuth.service.claimOrganization({
        actor: await harness.actorFor(human.userId),
        organizationId: account.organizationId,
        provisioning: {
          userId: account.identity.id,
          credentialId: account.credential.id,
          revokeAccess: true,
        },
      });

    const first = await claim();
    const second = await claim();

    expect(second).toEqual(first);
    expect(
      await harness.cfAuth.repository.countOrganizationOwners(account.organizationId),
    ).toBe(1);
  });

  it("refuses a second person once the organization has an owner", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    const first = await harness.sessions.human();
    const second = await harness.sessions.human();

    await harness.cfAuth.service.claimOrganization({
      actor: await harness.actorFor(first.userId),
      organizationId: account.organizationId,
    });

    await expect(
      harness.cfAuth.service.claimOrganization({
        actor: await harness.actorFor(second.userId),
        organizationId: account.organizationId,
      }),
    ).rejects.toMatchObject({ code: "not_claimable", status: 409 });
    expect(
      await harness.cfAuth.repository.findMembership(second.userId, account.organizationId),
    ).toBeNull();
  });

  it("refuses once the provisioning credential is no longer live", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    const human = await harness.sessions.human();
    await harness.cfAuth.service.revokeServiceApiKey({
      apiKeyId: account.credential.id,
      organizationId: account.organizationId,
    });

    await expect(
      harness.cfAuth.service.claimOrganization({
        actor: await harness.actorFor(human.userId),
        organizationId: account.organizationId,
        provisioning: {
          userId: account.identity.id,
          credentialId: account.credential.id,
          revokeAccess: false,
        },
      }),
    ).rejects.toMatchObject({ code: "not_claimable" });
  });

  it("refuses once the organization's own deadline has passed", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    const human = await harness.sessions.human();
    await setDeadline(harness, account.organizationId, past());

    await expect(
      harness.cfAuth.service.claimOrganization({
        actor: await harness.actorFor(human.userId),
        organizationId: account.organizationId,
      }),
    ).rejects.toMatchObject({ code: "not_claimable" });
  });

  it("refuses a session that has been signed out from under it", async () => {
    const harness = await createTestAuth();
    const account = await unclaimedAccount(harness);
    const human = await harness.sessions.human();
    const actor = await harness.actorFor(human.userId);
    const { session } = harness.cfAuth.config.tables;
    await harness.db.delete(session).where(eq(session.id, actor.actor!.credentialId!));

    await expect(
      harness.cfAuth.service.claimOrganization({
        actor,
        organizationId: account.organizationId,
      }),
    ).rejects.toMatchObject({ code: "not_claimable" });
  });
});
