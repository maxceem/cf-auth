import { describe, expect, it } from "vitest";
import { createTestAuth } from "./helpers.js";

describe("signup provisioning", () => {
  it("creates the user and a default organization owned by them", async () => {
    const harness = await createTestAuth();

    await harness.signUp({ email: "owner@example.com", password: "correct-horse-battery" });

    const user = await harness.cfAuth.repository.findUserByEmail("owner@example.com");
    expect(user).not.toBeNull();
    expect(user?.email).toBe("owner@example.com");

    const memberships = await harness.cfAuth.repository.listOrganizationsForUser(user!.id);
    expect(memberships).toHaveLength(1);
    expect(memberships[0]?.role).toBe("owner");
    expect(memberships[0]?.status).toBe("active");
    expect(memberships[0]?.organization.name).toBe("My Organization");

    expect(harness.errors).toEqual([]);
  });

  it("emits user.signup and organization.created events", async () => {
    const harness = await createTestAuth();

    await harness.signUp({ email: "events@example.com", password: "correct-horse-battery" });

    expect(harness.events.map((event) => event.type)).toEqual([
      "user.signup",
      "organization.created",
    ]);

    const created = harness.events.find((event) => event.type === "organization.created");
    expect(created).toMatchObject({ role: "owner", name: "My Organization" });
  });

  it("gives each user their own organization", async () => {
    const harness = await createTestAuth();

    await harness.signUp({ email: "first@example.com", password: "correct-horse-battery" });
    harness.jar.clear();
    await harness.signUp({ email: "second@example.com", password: "correct-horse-battery" });

    const first = await harness.cfAuth.repository.findUserByEmail("first@example.com");
    const second = await harness.cfAuth.repository.findUserByEmail("second@example.com");

    const firstOrgs = await harness.cfAuth.repository.listOrganizationsForUser(first!.id);
    const secondOrgs = await harness.cfAuth.repository.listOrganizationsForUser(second!.id);

    expect(firstOrgs).toHaveLength(1);
    expect(secondOrgs).toHaveLength(1);
    expect(firstOrgs[0]?.organization.id).not.toBe(secondOrgs[0]?.organization.id);
  });

  it("honours a configured default organization name function", async () => {
    const harness = await createTestAuth({
      organizations: {
        defaultOrganizationName: (user) => `${user.email.split("@")[0]}'s workspace`,
      },
    });

    await harness.signUp({ email: "dana@example.com", password: "correct-horse-battery" });

    const user = await harness.cfAuth.repository.findUserByEmail("dana@example.com");
    const memberships = await harness.cfAuth.repository.listOrganizationsForUser(user!.id);

    expect(memberships[0]?.organization.name).toBe("dana's workspace");
  });

  it("skips provisioning when auto-provisioning is disabled", async () => {
    const harness = await createTestAuth({
      organizations: { autoProvisionDefaultOrganization: false },
    });

    await harness.signUp({ email: "solo@example.com", password: "correct-horse-battery" });

    const user = await harness.cfAuth.repository.findUserByEmail("solo@example.com");
    expect(await harness.cfAuth.repository.listOrganizationsForUser(user!.id)).toEqual([]);

    const state = await harness.me();
    expect(state.authenticated).toBe(true);
    expect(state.organization).toBeNull();
    expect(state.role).toBeNull();
  });

  it("is idempotent — re-provisioning the same user does not create a second org", async () => {
    const harness = await createTestAuth();

    await harness.signUp({ email: "repeat@example.com", password: "correct-horse-battery" });
    const user = await harness.cfAuth.repository.findUserByEmail("repeat@example.com");

    await harness.cfAuth.service.provisionNewUser(user!);
    await harness.cfAuth.service.provisionNewUser(user!);

    expect(await harness.cfAuth.repository.listOrganizationsForUser(user!.id)).toHaveLength(1);
  });
});
