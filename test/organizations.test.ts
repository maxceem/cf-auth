import { describe, expect, it } from "vitest";
import { CfAuthError } from "../src/errors.js";
import { canManageOrganization, hasRoleAtLeast } from "../src/types.js";
import { requireOrganization, requireOrganizationManager, requireUser } from "../src/middleware.js";
import { createEmptyAuthState } from "../src/types.js";
import { createTestAuth, type TestAuth } from "./helpers.js";

const createUser = async (harness: TestAuth, email: string) => {
  harness.jar.clear();
  await harness.signUp({ email, password: "correct-horse-battery" });
  const user = await harness.cfAuth.repository.findUserByEmail(email);
  return user!;
};

describe("organization membership and roles", () => {
  it("resolves the role for each member of an organization", async () => {
    const harness = await createTestAuth();
    const owner = await createUser(harness, "owner@example.com");
    const member = await createUser(harness, "member@example.com");

    const [ownerOrg] = await harness.cfAuth.repository.listOrganizationsForUser(owner.id);
    const organizationId = ownerOrg!.organization.id;

    await harness.cfAuth.service.addOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: member.id,
      role: "member",
    });

    const membership = await harness.cfAuth.repository.findMembership(member.id, organizationId);
    expect(membership?.role).toBe("member");

    const members = await harness.cfAuth.service.listOrganizationMembers(owner.id, organizationId);
    expect(members.map((entry) => entry.email).sort()).toEqual([
      "member@example.com",
      "owner@example.com",
    ]);
    expect(members.find((entry) => entry.email === "member@example.com")?.role).toBe("member");
  });

  it("switches the current organization only for actual members", async () => {
    const harness = await createTestAuth();
    const owner = await createUser(harness, "switch-owner@example.com");
    const outsider = await createUser(harness, "outsider@example.com");

    const second = await harness.cfAuth.service.createOrganization(owner.id, "Second Org");
    const state = await harness.cfAuth.service.selectOrganization(
      owner.id,
      second.organization.id,
    );

    expect(state.organization?.name).toBe("Second Org");
    expect(state.role).toBe("owner");
    expect(state.memberships).toHaveLength(2);

    await expect(
      harness.cfAuth.service.selectOrganization(outsider.id, second.organization.id),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });
  });

  it("falls back to the first membership when the requested org is not one of them", async () => {
    const harness = await createTestAuth();
    const user = await createUser(harness, "fallback@example.com");

    const state = await harness.cfAuth.service.getAuthState(user.id, "00000000-0000-0000-0000-000000000000");

    expect(state?.organization).not.toBeNull();
    expect(state?.role).toBe("owner");
  });

  it("blocks non-managers from reading the member list", async () => {
    const harness = await createTestAuth();
    const owner = await createUser(harness, "list-owner@example.com");
    const member = await createUser(harness, "list-member@example.com");

    const [ownerOrg] = await harness.cfAuth.repository.listOrganizationsForUser(owner.id);
    const organizationId = ownerOrg!.organization.id;

    await harness.cfAuth.service.addOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: member.id,
      role: "member",
    });

    await expect(
      harness.cfAuth.service.listOrganizationMembers(member.id, organizationId),
    ).rejects.toBeInstanceOf(CfAuthError);
  });

  it("only lets an owner grant the owner role", async () => {
    const harness = await createTestAuth();
    const owner = await createUser(harness, "grant-owner@example.com");
    const admin = await createUser(harness, "grant-admin@example.com");
    const member = await createUser(harness, "grant-member@example.com");

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

    await expect(
      harness.cfAuth.service.updateOrganizationMemberRole({
        actorUserId: admin.id,
        organizationId,
        userId: member.id,
        role: "owner",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });

    const promoted = await harness.cfAuth.service.updateOrganizationMemberRole({
      actorUserId: admin.id,
      organizationId,
      userId: member.id,
      role: "admin",
    });
    expect(promoted.role).toBe("admin");
  });

  it("removes a member", async () => {
    const harness = await createTestAuth();
    const owner = await createUser(harness, "remove-owner@example.com");
    const member = await createUser(harness, "remove-member@example.com");

    const [ownerOrg] = await harness.cfAuth.repository.listOrganizationsForUser(owner.id);
    const organizationId = ownerOrg!.organization.id;

    await harness.cfAuth.service.addOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: member.id,
      role: "member",
    });

    const removed = await harness.cfAuth.service.removeOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: member.id,
    });

    expect(removed.role).toBe("member");
    expect(await harness.cfAuth.repository.findMembership(member.id, organizationId)).toBeNull();

    // Removing someone who is not a member is a 404, matching role updates.
    await expect(
      harness.cfAuth.service.removeOrganizationMember({
        actorUserId: owner.id,
        organizationId,
        userId: member.id,
      }),
    ).rejects.toMatchObject({ code: "not_a_member", status: 404 });
  });
});

describe("role helpers", () => {
  it("treats owner and admin as managers", () => {
    expect(canManageOrganization("owner")).toBe(true);
    expect(canManageOrganization("admin")).toBe(true);
    expect(canManageOrganization("member")).toBe(false);
    expect(canManageOrganization(null)).toBe(false);
  });

  it("orders roles owner > admin > member", () => {
    expect(hasRoleAtLeast("owner", "member")).toBe(true);
    expect(hasRoleAtLeast("admin", "admin")).toBe(true);
    expect(hasRoleAtLeast("member", "admin")).toBe(false);
    expect(hasRoleAtLeast(null, "member")).toBe(false);
  });
});

describe("route guards", () => {
  it("throws 401 for anonymous callers", () => {
    const state = createEmptyAuthState();

    expect(() => requireUser(state)).toThrow(CfAuthError);
    expect(() => requireUser(state)).toThrowError(expect.objectContaining({ status: 401 }));
    expect(() => requireOrganization(state)).toThrowError(
      expect.objectContaining({ status: 401 }),
    );
  });

  it("enforces a minimum role", async () => {
    const harness = await createTestAuth();
    const owner = await createUser(harness, "guard-owner@example.com");
    const member = await createUser(harness, "guard-member@example.com");

    const [ownerOrg] = await harness.cfAuth.repository.listOrganizationsForUser(owner.id);
    const organizationId = ownerOrg!.organization.id;

    await harness.cfAuth.service.addOrganizationMember({
      actorUserId: owner.id,
      organizationId,
      userId: member.id,
      role: "member",
    });

    const memberState = await harness.cfAuth.service.selectOrganization(member.id, organizationId);

    expect(requireOrganization(memberState).role).toBe("member");
    expect(() => requireOrganization(memberState, "admin")).toThrowError(
      expect.objectContaining({ status: 403 }),
    );
    expect(() => requireOrganizationManager(memberState)).toThrowError(
      expect.objectContaining({ status: 403 }),
    );

    const ownerState = await harness.cfAuth.service.selectOrganization(owner.id, organizationId);
    expect(requireOrganizationManager(ownerState).organization.id).toBe(organizationId);
  });
});
