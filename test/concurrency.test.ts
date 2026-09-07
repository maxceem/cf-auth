import { describe, expect, it } from "vitest";
import { createTestAuth, type TestAuth } from "./helpers.js";

const createUser = async (harness: TestAuth, email: string) => {
  harness.jar.clear();
  await harness.signUp({ email, password: "correct-horse-battery" });
  const user = await harness.cfAuth.repository.findUserByEmail(email);
  return user!;
};

/** An organization owned by two users. */
const createOrgWithTwoOwners = async (harness: TestAuth, prefix: string) => {
  const first = await createUser(harness, `${prefix}-first@example.com`);
  const second = await createUser(harness, `${prefix}-second@example.com`);

  const [membership] = await harness.cfAuth.repository.listOrganizationsForUser(first.id);
  const organizationId = membership!.organization.id;

  await harness.cfAuth.service.addOrganizationMember({
    actorUserId: first.id,
    organizationId,
    userId: second.id,
    role: "owner",
  });

  return { first, second, organizationId };
};

describe("last-owner guard is atomic", () => {
  it("survives two owners removing each other at once", async () => {
    const harness = await createTestAuth();
    const { first, second, organizationId } = await createOrgWithTwoOwners(harness, "race-remove");

    // Both pass an authorization check that says "there are 2 owners". Only the
    // conditional DELETE can keep them from both succeeding.
    const results = await Promise.all([
      harness.cfAuth.repository.removeOrganizationUser({
        organizationId,
        userId: first.id,
        requireAnotherOwner: true,
      }),
      harness.cfAuth.repository.removeOrganizationUser({
        organizationId,
        userId: second.id,
        requireAnotherOwner: true,
      }),
    ]);

    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(results.filter((result) => !result.ok)).toMatchObject([{ reason: "last_owner" }]);
    expect(await harness.cfAuth.repository.countOrganizationOwners(organizationId)).toBe(1);
  });

  it("survives two owners demoting each other at once", async () => {
    const harness = await createTestAuth();
    const { first, second, organizationId } = await createOrgWithTwoOwners(harness, "race-demote");

    const results = await Promise.all([
      harness.cfAuth.repository.updateOrganizationUserRole({
        organizationId,
        userId: first.id,
        role: "member",
        requireAnotherOwner: true,
      }),
      harness.cfAuth.repository.updateOrganizationUserRole({
        organizationId,
        userId: second.id,
        role: "member",
        requireAnotherOwner: true,
      }),
    ]);

    expect(results.filter((result) => result.ok)).toHaveLength(1);
    expect(await harness.cfAuth.repository.countOrganizationOwners(organizationId)).toBe(1);
  });

  it("still allows an unguarded write to touch a non-owner", async () => {
    const harness = await createTestAuth();
    const { first, organizationId } = await createOrgWithTwoOwners(harness, "race-member");
    const plain = await createUser(harness, "race-plain@example.com");

    await harness.cfAuth.service.addOrganizationMember({
      actorUserId: first.id,
      organizationId,
      userId: plain.id,
      role: "member",
    });

    // The guard must not block operations that cannot reduce the owner count.
    const result = await harness.cfAuth.repository.removeOrganizationUser({
      organizationId,
      userId: plain.id,
      requireAnotherOwner: true,
    });

    expect(result.ok).toBe(true);
    expect(await harness.cfAuth.repository.countOrganizationOwners(organizationId)).toBe(2);
  });
});

describe("default organization re-provisioning", () => {
  it("mints exactly one organization under concurrent re-provisioning", async () => {
    const harness = await createTestAuth();
    const { first, second, organizationId } = await createOrgWithTwoOwners(harness, "reprovision");

    await harness.cfAuth.service.removeOrganizationMember({
      actorUserId: second.id,
      organizationId,
      userId: first.id,
    });
    expect(await harness.cfAuth.repository.listOrganizationsForUser(first.id)).toEqual([]);

    const state = await harness.cfAuth.service.getAuthState(first.id, null);

    // Two requests land at once; a random org id would produce two orgs.
    const healed = await Promise.all([
      harness.cfAuth.service.ensureDefaultOrganization(state!),
      harness.cfAuth.service.ensureDefaultOrganization(state!),
    ]);

    const memberships = await harness.cfAuth.repository.listOrganizationsForUser(first.id);
    expect(memberships).toHaveLength(1);
    expect(healed[0]?.organization?.id).toBe(healed[1]?.organization?.id);
    expect(healed[0]?.organization?.id).not.toBe(organizationId);
  });

  it("walks to a new slot each time the user leaves their default organization", async () => {
    const harness = await createTestAuth();
    const user = await createUser(harness, "walker@example.com");
    const keeper = await createUser(harness, "keeper@example.com");

    const seen: string[] = [];

    for (let round = 0; round < 3; round += 1) {
      const [membership] = await harness.cfAuth.repository.listOrganizationsForUser(user.id);
      const organizationId = membership!.organization.id;
      seen.push(organizationId);

      // Hand the org to someone else, then leave it.
      await harness.cfAuth.service.addOrganizationMember({
        actorUserId: user.id,
        organizationId,
        userId: keeper.id,
        role: "owner",
      });
      await harness.cfAuth.service.removeOrganizationMember({
        actorUserId: keeper.id,
        organizationId,
        userId: user.id,
      });

      const state = await harness.cfAuth.service.getAuthState(user.id, null);
      await harness.cfAuth.service.ensureDefaultOrganization(state!);
    }

    // Three distinct organizations, and none of the abandoned ones re-entered.
    expect(new Set(seen).size).toBe(3);

    for (const organizationId of seen) {
      expect(await harness.cfAuth.repository.findMembership(user.id, organizationId)).toBeNull();
    }

    expect(await harness.cfAuth.repository.listOrganizationsForUser(user.id)).toHaveLength(1);
  });
});

describe("foreign key violations", () => {
  it("reports a missing user as 404 user_not_found, not a 500", async () => {
    const harness = await createTestAuth();
    const owner = await createUser(harness, "fk-owner@example.com");
    const [membership] = await harness.cfAuth.repository.listOrganizationsForUser(owner.id);

    await expect(
      harness.cfAuth.service.addOrganizationMember({
        actorUserId: owner.id,
        organizationId: membership!.organization.id,
        userId: "00000000-0000-0000-0000-00000000dead",
        role: "member",
      }),
    ).rejects.toMatchObject({ code: "user_not_found", status: 404 });
  });
});
