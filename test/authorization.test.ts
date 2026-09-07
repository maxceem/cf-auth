import { describe, expect, it } from "vitest";
import { createTestAuth, type TestAuth } from "./helpers.js";

const createUser = async (harness: TestAuth, email: string) => {
  harness.jar.clear();
  await harness.signUp({ email, password: "correct-horse-battery" });
  const user = await harness.cfAuth.repository.findUserByEmail(email);
  return user!;
};

/** An org owned by `owner`, with `admin` as admin and `member` as member. */
const createOrgWithRoles = async (harness: TestAuth, prefix: string) => {
  const owner = await createUser(harness, `${prefix}-owner@example.com`);
  const admin = await createUser(harness, `${prefix}-admin@example.com`);
  const member = await createUser(harness, `${prefix}-member@example.com`);
  const outsider = await createUser(harness, `${prefix}-outsider@example.com`);

  const [ownerOrg] = await harness.cfAuth.repository.listOrganizationsForUser(owner.id);
  const organizationId = ownerOrg!.organization.id;

  await harness.cfAuth.service.addOrganizationMember({
    actorUserId: owner.id,
    organizationId,
    userId: admin.id,
    role: "admin",
  });
  await harness.cfAuth.service.addOrganizationMember({
    actorUserId: owner.id,
    organizationId,
    userId: member.id,
    role: "member",
  });

  return { owner, admin, member, outsider, organizationId };
};

describe("owner authority cannot be reached by an admin", () => {
  it("blocks an admin from adding a new member as owner", async () => {
    const harness = await createTestAuth();
    const { admin, outsider, organizationId } = await createOrgWithRoles(harness, "add");

    await expect(
      harness.cfAuth.service.addOrganizationMember({
        actorUserId: admin.id,
        organizationId,
        userId: outsider.id,
        role: "owner",
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    expect(await harness.cfAuth.repository.findMembership(outsider.id, organizationId)).toBeNull();
  });

  it("lets an owner add a new member as owner", async () => {
    const harness = await createTestAuth();
    const { owner, outsider, organizationId } = await createOrgWithRoles(harness, "add-ok");

    const membership = await harness.cfAuth.service.addOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: outsider.id,
      role: "owner",
    });

    expect(membership.role).toBe("owner");
  });

  it("blocks an admin from demoting an owner", async () => {
    const harness = await createTestAuth();
    const { owner, admin, organizationId } = await createOrgWithRoles(harness, "demote");

    await expect(
      harness.cfAuth.service.updateOrganizationMemberRole({
        actorUserId: admin.id,
        organizationId,
        userId: owner.id,
        role: "member",
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    expect((await harness.cfAuth.repository.findMembership(owner.id, organizationId))?.role).toBe(
      "owner",
    );
  });

  it("blocks an admin from removing an owner", async () => {
    const harness = await createTestAuth();
    const { owner, admin, organizationId } = await createOrgWithRoles(harness, "remove");

    await expect(
      harness.cfAuth.service.removeOrganizationMember({
        actorUserId: admin.id,
        organizationId,
        userId: owner.id,
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    expect(await harness.cfAuth.repository.findMembership(owner.id, organizationId)).not.toBeNull();
  });

  it("blocks a plain member from managing anyone", async () => {
    const harness = await createTestAuth();
    const { member, outsider, organizationId } = await createOrgWithRoles(harness, "member");

    await expect(
      harness.cfAuth.service.addOrganizationMember({
        actorUserId: member.id,
        organizationId,
        userId: outsider.id,
        role: "member",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
  });

  it("blocks a non-member entirely", async () => {
    const harness = await createTestAuth();
    const { outsider, member, organizationId } = await createOrgWithRoles(harness, "outsider");

    await expect(
      harness.cfAuth.service.updateOrganizationMemberRole({
        actorUserId: outsider.id,
        organizationId,
        userId: member.id,
        role: "admin",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
  });
});

describe("last owner protection", () => {
  it("refuses to demote the only owner", async () => {
    const harness = await createTestAuth();
    const { owner, organizationId } = await createOrgWithRoles(harness, "last-demote");

    await expect(
      harness.cfAuth.service.updateOrganizationMemberRole({
        actorUserId: owner.id,
        organizationId,
        userId: owner.id,
        role: "admin",
      }),
    ).rejects.toMatchObject({ code: "last_owner", status: 409 });
  });

  it("refuses to remove the only owner", async () => {
    const harness = await createTestAuth();
    const { owner, organizationId } = await createOrgWithRoles(harness, "last-remove");

    await expect(
      harness.cfAuth.service.removeOrganizationMember({
        actorUserId: owner.id,
        organizationId,
        userId: owner.id,
      }),
    ).rejects.toMatchObject({ code: "last_owner", status: 409 });
  });

  it("allows it once a second owner exists", async () => {
    const harness = await createTestAuth();
    const { owner, outsider, organizationId } = await createOrgWithRoles(harness, "second-owner");

    await harness.cfAuth.service.addOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: outsider.id,
      role: "owner",
    });

    const removed = await harness.cfAuth.service.removeOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: owner.id,
    });

    expect(removed.organization.id).toBe(organizationId);
    expect(removed.role).toBe("owner");
    expect(await harness.cfAuth.repository.countOrganizationOwners(organizationId)).toBe(1);
  });
});

describe("duplicate membership", () => {
  it("reports a 409 rather than a raw constraint error", async () => {
    const harness = await createTestAuth();
    const { owner, member, organizationId } = await createOrgWithRoles(harness, "dup");

    await expect(
      harness.cfAuth.service.addOrganizationMember({
        actorUserId: owner.id,
        organizationId,
        userId: member.id,
        role: "member",
      }),
    ).rejects.toMatchObject({ code: "already_a_member", status: 409 });
  });
});

describe("api key authorization", () => {
  it("refuses to mint a key for an organization the actor does not belong to", async () => {
    const harness = await createTestAuth();
    const { outsider, organizationId } = await createOrgWithRoles(harness, "key-outsider");

    await expect(
      harness.cfAuth.service.createApiKey({
        organizationId,
        actorUserId: outsider.id,
        name: "Stolen",
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });

    expect(await harness.cfAuth.repository.listApiKeys(organizationId)).toEqual([]);
  });

  it("refuses to mint a key for a plain member", async () => {
    const harness = await createTestAuth();
    const { member, organizationId } = await createOrgWithRoles(harness, "key-member");

    await expect(
      harness.cfAuth.service.createApiKey({
        organizationId,
        actorUserId: member.id,
        name: "Escalation",
      }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });
  });

  it("allows owners and admins to mint keys", async () => {
    const harness = await createTestAuth();
    const { owner, admin, organizationId } = await createOrgWithRoles(harness, "key-manager");

    for (const actor of [owner, admin]) {
      const key = await harness.cfAuth.service.createApiKey({
        organizationId,
        actorUserId: actor.id,
        name: `Key for ${actor.email}`,
      });

      expect(key.organizationId).toBe(organizationId);
    }
  });

  it("lets any member list keys but not outsiders", async () => {
    const harness = await createTestAuth();
    const { owner, member, outsider, organizationId } = await createOrgWithRoles(harness, "key-list");

    await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: owner.id,
      name: "Listed",
    });

    const listed = await harness.cfAuth.service.listApiKeys({
      organizationId,
      actorUserId: member.id,
    });
    expect(listed).toHaveLength(1);

    await expect(
      harness.cfAuth.service.listApiKeys({ organizationId, actorUserId: outsider.id }),
    ).rejects.toMatchObject({ code: "forbidden" });
  });

  it("refuses revocation by a member or an outsider", async () => {
    const harness = await createTestAuth();
    const { owner, member, outsider, organizationId } = await createOrgWithRoles(
      harness,
      "key-revoke",
    );

    const key = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: owner.id,
      name: "Target",
    });

    for (const actor of [member, outsider]) {
      await expect(
        harness.cfAuth.service.revokeApiKey({
          organizationId,
          actorUserId: actor.id,
          apiKeyId: key.id,
        }),
      ).rejects.toMatchObject({ code: "forbidden" });
    }

    expect((await harness.cfAuth.repository.findApiKeyById(key.id, organizationId))?.revokedAt).toBeNull();
  });
});
