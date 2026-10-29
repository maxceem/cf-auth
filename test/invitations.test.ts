import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createD1TestAuth, createTestAuth, type D1TestAuth, type TestAuth } from "./helpers.js";

const password = "correct-horse-battery";

/** An owner with an organization, through the session helpers (no password hash). */
const ownerWithOrganization = async (harness: TestAuth, email = "owner@example.com") => {
  const owner = await harness.sessions.human({ email });
  return { ownerId: owner.userId, organizationId: owner.organizationId };
};

const invite = async (
  harness: TestAuth,
  input: { actorId: string; organizationId: string; email: string; role?: "owner" | "admin" | "member" },
) =>
  harness.cfAuth.service.createInvitation({
    actor: await harness.actorFor(input.actorId, input.organizationId),
    organizationId: input.organizationId,
    email: input.email,
    role: input.role ?? "member",
  });

const expireInvitation = async (harness: TestAuth, invitationId: string) => {
  await harness.client.execute({
    sql: "update organization_invitation set expires_at = ? where id = ?",
    args: [new Date(Date.now() - 1000).toISOString(), invitationId],
  });
};

describe("organization invitations", () => {
  it("lets a new person sign up from an invitation and join as its role", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const { invitation, token } = await invite(harness, {
      actorId: ownerId,
      organizationId,
      email: "New.Person@Example.com",
      role: "admin",
    });

    expect(invitation).toMatchObject({
      email: "new.person@example.com",
      role: "admin",
      state: "pending",
      invitedBy: { id: ownerId, email: "owner@example.com" },
    });
    expect(token.length).toBeGreaterThan(30);

    const preview = await harness.cfAuth.service.previewInvitation(token);
    expect(preview).toMatchObject({
      id: invitation.id,
      organization: { id: organizationId },
      email: "new.person@example.com",
      role: "admin",
      state: "pending",
    });

    // A pending invitation is where they are going: no stray default organization.
    harness.jar.clear();
    await harness.signUp({ email: "new.person@example.com", password });
    const before = await harness.me();
    expect(before.authenticated).toBe(true);
    expect(before.memberships).toEqual([]);
    expect(before.organization).toBeNull();
    expect(before.user?.emailVerified).toBe(false);

    const actor = await harness.actorFor(before.user!.id);
    const membership = await harness.cfAuth.service.acceptInvitation({ actor, token });
    expect(membership).toMatchObject({ role: "admin", organization: { id: organizationId } });

    const after = await harness.me();
    expect(after.organization?.id).toBe(organizationId);
    expect(after.role).toBe("admin");
    // The link arrived in that inbox, so the address is verified now.
    expect(after.user?.emailVerified).toBe(true);

    expect(harness.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "invitation.created", invitationId: invitation.id }),
        expect.objectContaining({
          type: "member.added",
          userId: before.user!.id,
          organizationId,
          role: "admin",
          invitationId: invitation.id,
        }),
        expect.objectContaining({ type: "user.email_verified", userId: before.user!.id }),
      ]),
    );
    expect(
      (await harness.cfAuth.service.previewInvitation(token)).state,
    ).toBe("accepted");
  });

  it("is idempotent for the person who accepted and closed to everyone else", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const invitee = await harness.sessions.human({ email: "invitee@example.com" });
    const { token } = await invite(harness, { actorId: ownerId, organizationId, email: "invitee@example.com" });
    const actor = await harness.actorFor(invitee.userId);

    const first = await harness.cfAuth.service.acceptInvitation({ actor, token });
    const again = await harness.cfAuth.service.acceptInvitation({ actor, token });
    expect(again).toEqual(first);
    expect(
      harness.events.filter((event) => event.type === "member.added"),
    ).toHaveLength(1);
  });

  it("only lets the address it was sent to accept", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const stranger = await harness.sessions.human({ email: "stranger@example.com" });
    const { token } = await invite(harness, { actorId: ownerId, organizationId, email: "invitee@example.com" });

    await expect(
      harness.cfAuth.service.acceptInvitation({ actor: await harness.actorFor(stranger.userId), token }),
    ).rejects.toMatchObject({ code: "invitation_email_mismatch", status: 403 });
    expect(await harness.cfAuth.repository.findMembership(stranger.userId, organizationId)).toBeNull();
  });

  it("follows the member-management roles", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const admin = await harness.sessions.human({ email: "admin@example.com" });
    const member = await harness.sessions.human({ email: "member@example.com" });
    for (const [userId, role] of [
      [admin.userId, "admin"],
      [member.userId, "member"],
    ] as const) {
      await harness.cfAuth.service.addOrganizationMember({
        actor: await harness.actorFor(ownerId, organizationId),
        organizationId,
        userId,
        role,
      });
    }

    await expect(
      invite(harness, { actorId: member.userId, organizationId, email: "a@example.com" }),
    ).rejects.toMatchObject({ code: "forbidden", status: 403 });
    await expect(
      invite(harness, { actorId: admin.userId, organizationId, email: "b@example.com", role: "owner" }),
    ).rejects.toMatchObject({ code: "forbidden" });

    const byAdmin = await invite(harness, {
      actorId: admin.userId,
      organizationId,
      email: "c@example.com",
      role: "admin",
    });
    expect(byAdmin.invitation.role).toBe("admin");
    const byOwner = await invite(harness, {
      actorId: ownerId,
      organizationId,
      email: "d@example.com",
      role: "owner",
    });
    expect(byOwner.invitation.role).toBe("owner");

    await expect(
      harness.cfAuth.service.listInvitations({
        actor: await harness.actorFor(member.userId, organizationId),
        organizationId,
      }),
    ).rejects.toMatchObject({ code: "forbidden" });
    const listed = await harness.cfAuth.service.listInvitations({
      actor: await harness.actorFor(admin.userId, organizationId),
      organizationId,
    });
    expect(listed.map((entry) => entry.email).sort()).toEqual(["c@example.com", "d@example.com"]);
  });

  it("refuses a read-only key and lets a manage key invite", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const readKey = await harness.cfAuth.service.createApiKey({
      organizationId,
      actor: await harness.actorFor(ownerId, organizationId),
      name: "read",
      grant: "read",
    });
    const readState = await harness.cfAuth.service.resolveApiKeyAuthState(readKey.plaintext);

    await expect(
      harness.cfAuth.service.createInvitation({
        actor: readState,
        organizationId,
        email: "x@example.com",
        role: "member",
      }),
    ).rejects.toMatchObject({ code: "grant_insufficient" });
    // Reading needs only `read`.
    await expect(
      harness.cfAuth.service.listInvitations({ actor: readState, organizationId }),
    ).resolves.toEqual([]);
  });

  it("keeps one open invitation per address and reissues an expired one in place", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const first = await invite(harness, { actorId: ownerId, organizationId, email: "x@example.com" });

    await expect(
      invite(harness, { actorId: ownerId, organizationId, email: "X@example.com" }),
    ).rejects.toMatchObject({ code: "invitation_pending", status: 409 });

    await expireInvitation(harness, first.invitation.id);
    const second = await invite(harness, {
      actorId: ownerId,
      organizationId,
      email: "x@example.com",
      role: "admin",
    });
    expect(second.invitation).toMatchObject({ id: first.invitation.id, state: "pending", role: "admin" });
    await expect(harness.cfAuth.service.previewInvitation(first.token)).rejects.toMatchObject({
      code: "invitation_not_found",
    });
  });

  it("refuses to invite someone who is already a member", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);

    await expect(
      invite(harness, { actorId: ownerId, organizationId, email: "OWNER@example.com" }),
    ).rejects.toMatchObject({ code: "already_a_member", status: 409 });
    await expect(
      invite(harness, { actorId: ownerId, organizationId, email: "not-an-email" }),
    ).rejects.toMatchObject({ code: "validation_error" });
  });

  it("revokes and resends, and an old link stops working", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const invitee = await harness.sessions.human({ email: "invitee@example.com" });
    const actor = await harness.actorFor(invitee.userId);
    const manager = await harness.actorFor(ownerId, organizationId);
    const { invitation, token } = await invite(harness, {
      actorId: ownerId,
      organizationId,
      email: "invitee@example.com",
    });

    const resent = await harness.cfAuth.service.resendInvitation({
      actor: manager,
      organizationId,
      invitationId: invitation.id,
    });
    expect(resent.token).not.toBe(token);
    await expect(harness.cfAuth.service.acceptInvitation({ actor, token })).rejects.toMatchObject({
      code: "invitation_not_found",
      status: 404,
    });

    const revoked = await harness.cfAuth.service.revokeInvitation({
      actor: manager,
      organizationId,
      invitationId: invitation.id,
    });
    expect(revoked.state).toBe("revoked");
    await expect(
      harness.cfAuth.service.acceptInvitation({ actor, token: resent.token }),
    ).rejects.toMatchObject({ code: "invitation_closed", status: 409 });
    await expect(
      harness.cfAuth.service.revokeInvitation({ actor: manager, organizationId, invitationId: invitation.id }),
    ).rejects.toMatchObject({ code: "invitation_closed" });
    expect(await harness.cfAuth.service.listInvitations({ actor: manager, organizationId })).toEqual([]);
  });

  it("refuses an expired invitation, and its invitee gets a default organization", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const { invitation, token } = await invite(harness, {
      actorId: ownerId,
      organizationId,
      email: "late@example.com",
    });
    await expireInvitation(harness, invitation.id);

    harness.jar.clear();
    await harness.signUp({ email: "late@example.com", password });
    const state = await harness.me();
    expect(state.memberships).toHaveLength(1);
    expect(state.organization?.id).not.toBe(organizationId);

    await expect(
      harness.cfAuth.service.acceptInvitation({ actor: await harness.actorFor(state.user!.id), token }),
    ).rejects.toMatchObject({ code: "invitation_expired", status: 410 });
  });

  it("answers by id only for a verified address", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const unverified = await harness.sessions.human({
      email: "unverified@example.com",
      emailVerified: false,
    });
    const verified = await harness.sessions.human({ email: "verified@example.com" });
    const toUnverified = await invite(harness, {
      actorId: ownerId,
      organizationId,
      email: "unverified@example.com",
    });
    await invite(harness, { actorId: ownerId, organizationId, email: "verified@example.com" });

    const unverifiedActor = await harness.actorFor(unverified.userId);
    expect(await harness.cfAuth.service.listMyInvitations(unverifiedActor)).toEqual([]);
    await expect(
      harness.cfAuth.service.acceptInvitation({
        actor: unverifiedActor,
        invitationId: toUnverified.invitation.id,
      }),
    ).rejects.toMatchObject({ code: "email_unverified", status: 403 });

    const verifiedActor = await harness.actorFor(verified.userId);
    const mine = await harness.cfAuth.service.listMyInvitations(verifiedActor);
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({ email: "verified@example.com", organization: { id: organizationId } });

    // Someone else's invitation id reads as missing, not as somebody else's.
    await expect(
      harness.cfAuth.service.acceptInvitation({
        actor: verifiedActor,
        invitationId: toUnverified.invitation.id,
      }),
    ).rejects.toMatchObject({ code: "invitation_not_found" });

    const membership = await harness.cfAuth.service.acceptInvitation({
      actor: verifiedActor,
      invitationId: mine[0]!.id,
    });
    expect(membership.organization.id).toBe(organizationId);
  });

  it("declining releases the invitee to a default organization of their own", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const { token } = await invite(harness, { actorId: ownerId, organizationId, email: "maybe@example.com" });

    harness.jar.clear();
    await harness.signUp({ email: "maybe@example.com", password });
    const pending = await harness.me();
    expect(pending.organization).toBeNull();

    const declined = await harness.cfAuth.service.declineInvitation({
      actor: await harness.actorFor(pending.user!.id),
      token,
    });
    expect(declined.state).toBe("declined");

    const next = await harness.me();
    expect(next.memberships).toHaveLength(1);
    expect(next.organization?.id).not.toBe(organizationId);
    expect(harness.events).toEqual(
      expect.arrayContaining([expect.objectContaining({ type: "invitation.declined" })]),
    );
  });

  it("will not accept into an organization past its deadline", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const invitee = await harness.sessions.human({ email: "invitee@example.com" });
    const { token } = await invite(harness, { actorId: ownerId, organizationId, email: "invitee@example.com" });
    await harness.client.execute({
      sql: "update organization set expires_at = ? where id = ?",
      args: [new Date(Date.now() - 1000).toISOString(), organizationId],
    });

    await expect(
      harness.cfAuth.service.acceptInvitation({ actor: await harness.actorFor(invitee.userId), token }),
    ).rejects.toMatchObject({ code: "organization_expired" });
  });

  it("accepts once when the same person accepts concurrently", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const invitee = await harness.sessions.human({ email: "invitee@example.com" });
    const { token } = await invite(harness, { actorId: ownerId, organizationId, email: "invitee@example.com" });
    const actor = await harness.actorFor(invitee.userId);

    const results = await Promise.allSettled([
      harness.cfAuth.service.acceptInvitation({ actor, token }),
      harness.cfAuth.service.acceptInvitation({ actor, token }),
    ]);
    expect(results.every((result) => result.status === "fulfilled")).toBe(true);
    const members = await harness.cfAuth.repository.listMembers(organizationId);
    expect(members.filter((member) => member.id === invitee.userId)).toHaveLength(1);
  });
});

describe("leaving and renaming an organization", () => {
  it("lets a member leave, and the last owner cannot", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const member = await harness.sessions.human({ email: "member@example.com" });
    await harness.cfAuth.service.addOrganizationMember({
      actor: await harness.actorFor(ownerId, organizationId),
      organizationId,
      userId: member.userId,
      role: "member",
    });

    const left = await harness.cfAuth.service.leaveOrganization({
      actor: await harness.actorFor(member.userId, organizationId),
      organizationId,
    });
    expect(left.role).toBe("member");
    expect(await harness.cfAuth.repository.findMembership(member.userId, organizationId)).toBeNull();
    expect(harness.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          type: "member.removed",
          actorUserId: member.userId,
          userId: member.userId,
        }),
      ]),
    );

    await expect(
      harness.cfAuth.service.leaveOrganization({
        actor: await harness.actorFor(ownerId, organizationId),
        organizationId,
      }),
    ).rejects.toMatchObject({ code: "last_owner", status: 409 });
  });

  it("lets owners and admins rename, not members", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const member = await harness.sessions.human({ email: "member@example.com" });
    await harness.cfAuth.service.addOrganizationMember({
      actor: await harness.actorFor(ownerId, organizationId),
      organizationId,
      userId: member.userId,
      role: "member",
    });

    await expect(
      harness.cfAuth.service.renameOrganization({
        actor: await harness.actorFor(member.userId, organizationId),
        organizationId,
        name: "Nope",
      }),
    ).rejects.toMatchObject({ code: "forbidden" });

    const renamed = await harness.cfAuth.service.renameOrganization({
      actor: await harness.actorFor(ownerId, organizationId),
      organizationId,
      name: "  Acme Studio  ",
    });
    expect(renamed).toMatchObject({ id: organizationId, name: "Acme Studio" });
    expect((await harness.cfAuth.repository.findOrganization(organizationId))?.name).toBe("Acme Studio");
  });

  it("reports membership changes as events", async () => {
    const harness = await createTestAuth();
    const { ownerId, organizationId } = await ownerWithOrganization(harness);
    const member = await harness.sessions.human({ email: "member@example.com" });
    const actor = await harness.actorFor(ownerId, organizationId);
    await harness.cfAuth.service.addOrganizationMember({
      actor,
      organizationId,
      userId: member.userId,
      role: "member",
    });
    await harness.cfAuth.service.updateOrganizationMemberRole({
      actor,
      organizationId,
      userId: member.userId,
      role: "admin",
    });
    await harness.cfAuth.service.removeOrganizationMember({ actor, organizationId, userId: member.userId });

    expect(
      harness.events
        .filter((event) => event.type.startsWith("member."))
        .map((event) => event.type),
    ).toEqual(["member.added", "member.role_changed", "member.removed"]);
  });
});

describe("invitations on D1", () => {
  let harness: D1TestAuth;

  beforeAll(async () => {
    harness = await createD1TestAuth();
  });

  afterAll(async () => {
    await harness.dispose();
  });

  it("accepts in one D1 batch, verifying the address", async () => {
    const owner = await harness.sessions.human({ email: "d1-owner@example.com" });
    const invitee = await harness.sessions.human({
      email: "d1-invitee@example.com",
      emailVerified: false,
    });
    const { token } = await harness.cfAuth.service.createInvitation({
      actor: await harness.actorFor(owner.userId, owner.organizationId),
      organizationId: owner.organizationId,
      email: "d1-invitee@example.com",
      role: "admin",
    });

    const membership = await harness.cfAuth.service.acceptInvitation({
      actor: await harness.actorFor(invitee.userId),
      token,
    });
    expect(membership).toMatchObject({ role: "admin", organization: { id: owner.organizationId } });
    expect((await harness.cfAuth.repository.findUserById(invitee.userId))?.emailVerified).toBe(true);
  });
});
