import { describe, expect, it } from "vitest";
import { requireGrant } from "../src/middleware.js";
import { createEmptyAuthState, type CredentialGrant } from "../src/types.js";
import { createTestAuth, type TestAuth } from "./helpers.js";

const expectCode = async (promise: Promise<unknown>, code: string) => {
  await expect(promise).rejects.toMatchObject({ code });
};

/** An owner, their session state, and a key of theirs with `grant`, resolved as a request would. */
const ownerWithKey = async (harness: TestAuth, grant: CredentialGrant) => {
  const owner = await harness.sessions.human();
  const session = await harness.actorFor(owner.userId);
  const key = await harness.cfAuth.service.createApiKey({
    organizationId: owner.organizationId,
    actor: session,
    name: `${grant} key`,
    grant,
  });
  const state = await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext);
  return { owner, session, key, state };
};

describe("credential grants", () => {
  it("resolve into the auth state: null anonymous, manage for a session, the key's own for a key", async () => {
    const harness = await createTestAuth();
    const { session, key, state } = await ownerWithKey(harness, "read");

    expect(createEmptyAuthState().grant).toBeNull();
    expect((await harness.me({ useJar: false })).grant).toBeNull();
    expect(session.grant).toBe("manage");
    expect(key.grant).toBe("read");
    expect(state).toMatchObject({ authenticated: true, credentialType: "apiKey", grant: "read" });

    // The middleware resolves the same grant from the bearer token.
    const viaRequest = await harness.me({
      useJar: false,
      headers: { Authorization: `Bearer ${key.plaintext}` },
    });
    expect(viaRequest.grant).toBe("read");
  });

  it("default to manage for a key issued without one", async () => {
    const harness = await createTestAuth();
    const owner = await harness.sessions.human();
    const key = await harness.cfAuth.service.createApiKey({
      organizationId: owner.organizationId,
      actor: await harness.actorFor(owner.userId),
      name: "Default",
    });

    expect(key.grant).toBe("manage");
    expect((await harness.cfAuth.service.resolveApiKeyAuthState(key.plaintext)).grant).toBe("manage");
  });

  it("default to manage at the repository boundary, in the row and in the answer alike", async () => {
    const harness = await createTestAuth();
    const owner = await harness.sessions.human();
    const { repository } = harness.cfAuth;
    const base = {
      userId: owner.userId,
      organizationId: owner.organizationId,
      name: "Direct",
      tokenHint: "abcd",
      enabled: true,
      expiresAt: null,
      source: "console",
      label: null,
    };

    const omitted = await repository.createApiKey({ ...base, tokenHash: "hash-omitted" });
    expect(omitted.grant).toBe("manage");
    expect((await repository.findApiKeyById(omitted.id, owner.organizationId))?.grant).toBe("manage");

    const read = await repository.createApiKey({ ...base, tokenHash: "hash-read", grant: "read" });
    expect(read.grant).toBe("read");
    expect((await repository.findApiKeyById(read.id, owner.organizationId))?.grant).toBe("read");

    await expectCode(
      repository.createApiKey({ ...base, tokenHash: "hash-bad", grant: "all" as CredentialGrant }),
      "validation_error",
    );
  });

  it("are taken as given by trusted service issuance", async () => {
    const harness = await createTestAuth();
    const identity = await harness.cfAuth.service.createServiceIdentity({ name: "Reporter" });
    const membership = await harness.cfAuth.service.createOrganization(identity.id, "Reports");
    const organizationId = membership.organization.id;

    const reader = await harness.cfAuth.service.issueServiceApiKey({
      userId: identity.id,
      organizationId,
      name: "Read only",
      grant: "read",
    });
    const manager = await harness.cfAuth.service.issueServiceApiKey({
      userId: identity.id,
      organizationId,
      name: "Default",
    });

    expect(reader.grant).toBe("read");
    expect(manager.grant).toBe("manage");
    expect(await harness.cfAuth.service.resolveApiKeyAuthState(reader.plaintext)).toMatchObject({
      authenticated: true,
      user: { id: identity.id, kind: "service" },
      grant: "read",
    });
    await expectCode(
      harness.cfAuth.service.issueServiceApiKey({
        userId: identity.id,
        organizationId,
        name: "Bad",
        grant: "admin" as CredentialGrant,
      }),
      "validation_error",
    );
  });

  it("let a read key read", async () => {
    const harness = await createTestAuth();
    const { owner, key, state } = await ownerWithKey(harness, "read");

    const keys = await harness.cfAuth.service.listApiKeys({
      organizationId: owner.organizationId,
      actor: state,
    });
    expect(keys).toEqual([expect.objectContaining({ id: key.id, grant: "read" })]);
    const members = await harness.cfAuth.service.listOrganizationMembers({
      organizationId: owner.organizationId,
      actor: state,
    });
    expect(members.map((member) => member.id)).toEqual([owner.userId]);
  });

  it("refuse every write to a read key, even its owner's", async () => {
    const harness = await createTestAuth();
    const { owner, key, state } = await ownerWithKey(harness, "read");
    const { service } = harness.cfAuth;
    const other = await harness.sessions.human();
    const organizationId = owner.organizationId;

    await expectCode(
      service.addOrganizationMember({ actor: state, organizationId, userId: other.userId, role: "member" }),
      "grant_insufficient",
    );
    await expectCode(
      service.updateOrganizationMemberRole({ actor: state, organizationId, userId: owner.userId, role: "admin" }),
      "grant_insufficient",
    );
    await expectCode(
      service.removeOrganizationMember({ actor: state, organizationId, userId: owner.userId }),
      "grant_insufficient",
    );
    for (const grant of ["read", "manage"] as const) {
      await expectCode(
        service.createApiKey({ actor: state, organizationId, name: "Child", grant }),
        "grant_insufficient",
      );
    }
    await expectCode(
      service.revokeApiKey({ actor: state, organizationId, apiKeyId: key.id }),
      "grant_insufficient",
    );
    await expectCode(service.claimOrganization({ actor: state, organizationId }), "grant_insufficient");
    expect(() => service.claimOrganizationStatements({ actor: state, organizationId })).toThrow(
      expect.objectContaining({ code: "grant_insufficient", status: 403 }),
    );

    // Nothing changed: still one member, one live key.
    expect((await service.listOrganizationMembers({ actor: state, organizationId })).length).toBe(1);
    expect(await service.listApiKeys({ actor: state, organizationId })).toEqual([
      expect.objectContaining({ id: key.id, revokedAt: null }),
    ]);
  });

  it("still let a read key end itself", async () => {
    const harness = await createTestAuth();
    const { key, state } = await ownerWithKey(harness, "read");

    const revoked = await harness.cfAuth.service.revokeOwnApiKey({ actor: state });
    expect(revoked).toMatchObject({ id: key.id, enabled: false, grant: "read" });
  });

  it("are judged after the organization binding", async () => {
    const harness = await createTestAuth();
    const { state } = await ownerWithKey(harness, "read");
    const elsewhere = await harness.sessions.human();

    // A read key reaching into another organization is told about the
    // organization, whether the call reads or writes.
    await expectCode(
      harness.cfAuth.service.listApiKeys({ actor: state, organizationId: elsewhere.organizationId }),
      "forbidden",
    );
    await expectCode(
      harness.cfAuth.service.createApiKey({
        actor: state,
        organizationId: elsewhere.organizationId,
        name: "Reach",
      }),
      "forbidden",
    );
  });

  it("put the organization binding before the grant in a claim", async () => {
    const harness = await createTestAuth();
    const { state: reader } = await ownerWithKey(harness, "read");
    const { state: manager } = await ownerWithKey(harness, "manage");
    const elsewhere = await harness.sessions.human();
    const organizationId = elsewhere.organizationId;

    for (const actor of [reader, manager]) {
      await expectCode(harness.cfAuth.service.claimOrganization({ actor, organizationId }), "forbidden");
      expect(() => harness.cfAuth.service.claimOrganizationStatements({ actor, organizationId })).toThrow(
        expect.objectContaining({ code: "forbidden", status: 403 }),
      );
    }
  });

  it("put the grant before the session requirement of a claim", async () => {
    const harness = await createTestAuth();
    const { owner, state } = await ownerWithKey(harness, "manage");

    // A manage key in its own organization has the grant, so what it lacks is a session.
    await expectCode(
      harness.cfAuth.service.claimOrganization({ actor: state, organizationId: owner.organizationId }),
      "session_required",
    );
    expect(() =>
      harness.cfAuth.service.claimOrganizationStatements({ actor: state, organizationId: owner.organizationId }),
    ).toThrow(expect.objectContaining({ code: "session_required" }));
  });

  it("bound what a credential may issue", async () => {
    const harness = await createTestAuth();
    const { owner, session, state } = await ownerWithKey(harness, "manage");
    const { service } = harness.cfAuth;
    const organizationId = owner.organizationId;

    for (const actor of [state, session]) {
      for (const grant of ["read", "manage"] as const) {
        const issued = await service.createApiKey({ actor, organizationId, name: `${grant} child`, grant });
        expect(issued.grant).toBe(grant);
        expect((await service.resolveApiKeyAuthState(issued.plaintext)).grant).toBe(grant);
      }
    }
    await expectCode(
      service.createApiKey({ actor: session, organizationId, name: "Bad", grant: "all" as CredentialGrant }),
      "validation_error",
    );
  });

  it("gate an app's own writes through requireGrant", async () => {
    const harness = await createTestAuth();
    const { session, state: reader } = await ownerWithKey(harness, "read");
    const { state: manager } = await ownerWithKey(harness, "manage");

    expect(() => requireGrant(createEmptyAuthState(), "read")).toThrow(
      expect.objectContaining({ code: "unauthorized", status: 401 }),
    );
    expect(requireGrant(reader, "read")).toBe(reader);
    expect(() => requireGrant(reader, "manage")).toThrow(
      expect.objectContaining({
        code: "grant_insufficient",
        status: 403,
        message: expect.stringContaining("use a session or a key with the manage grant"),
      }),
    );
    expect(requireGrant(manager, "manage")).toBe(manager);
    expect(requireGrant(session, "manage")).toBe(session);
  });
});
