import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { requireOrganization, requireUser, type CfAuthVariables } from "../src/middleware.js";
import { createTestAuth, testBaseUrl, type TestAuth } from "./helpers.js";

const createUser = async (harness: TestAuth, email: string) => {
  harness.jar.clear();
  await harness.signUp({ email, password: "correct-horse-battery" });
  const user = await harness.cfAuth.repository.findUserByEmail(email);
  return user!;
};

describe("requireUser vs API-key callers", () => {
  it("returns 403 session_required rather than 401 for an API key", async () => {
    const harness = await createTestAuth();
    const user = await createUser(harness, "guard-key@example.com");
    const [membership] = await harness.cfAuth.repository.listOrganizationsForUser(user.id);
    const organizationId = membership!.organization.id;

    const key = await harness.cfAuth.service.createApiKey({
      organizationId,
      actorUserId: user.id,
      name: "Machine",
    });

    const app = new Hono<{ Variables: CfAuthVariables }>();
    app.use("*", harness.cfAuth.middleware());
    app.get("/session-only", (c) => c.json(requireUser(c.get("authState"))));
    app.get("/either", (c) => c.json(requireOrganization(c.get("authState")).organization));
    app.onError((error, c) =>
      c.json({ code: (error as { code?: string }).code }, (error as { status?: 200 }).status ?? 500),
    );

    const headers = { Authorization: `Bearer ${key.plaintext}` };

    const sessionOnly = await app.request(`${testBaseUrl}/session-only`, { headers });
    expect(sessionOnly.status).toBe(403);
    expect(await sessionOnly.json()).toEqual({ code: "session_required" });

    // The same key is perfectly valid for an org-scoped endpoint.
    const either = await app.request(`${testBaseUrl}/either`, { headers });
    expect(either.status).toBe(200);

    // Anonymous still gets a 401, so clients can distinguish the two.
    const anonymous = await app.request(`${testBaseUrl}/session-only`);
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toEqual({ code: "unauthorized" });
  });
});

describe("middleware options", () => {
  it("ignores bearer tokens when apiKeys is disabled per call", async () => {
    const harness = await createTestAuth();
    const user = await createUser(harness, "percall@example.com");
    const [membership] = await harness.cfAuth.repository.listOrganizationsForUser(user.id);

    const key = await harness.cfAuth.service.createApiKey({
      organizationId: membership!.organization.id,
      actorUserId: user.id,
      name: "Ignored",
    });

    const app = new Hono<{ Variables: CfAuthVariables }>();
    app.use("/closed/*", harness.cfAuth.middleware({ apiKeys: false }));
    app.use("/open/*", harness.cfAuth.middleware({ apiKeys: true }));
    app.get("/closed/me", (c) => c.json(c.get("authState")));
    app.get("/open/me", (c) => c.json(c.get("authState")));

    const headers = { Authorization: `Bearer ${key.plaintext}` };

    const closed = await (await app.request(`${testBaseUrl}/closed/me`, { headers })).json();
    expect(closed).toMatchObject({ authenticated: false, credentialType: null });

    const open = await (await app.request(`${testBaseUrl}/open/me`, { headers })).json();
    expect(open).toMatchObject({ authenticated: true, credentialType: "apiKey" });
  });

  it("does not touch the cookie when syncCurrentOrganizationCookie is false", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "nosync@example.com", password: "correct-horse-battery" });
    const cookieName = harness.cfAuth.currentOrganizationCookie.name;

    const app = new Hono<{ Variables: CfAuthVariables }>();
    app.use("/quiet/*", harness.cfAuth.middleware({ syncCurrentOrganizationCookie: false }));
    app.use("/loud/*", harness.cfAuth.middleware());
    app.get("/quiet/me", (c) => c.json(c.get("authState")));
    app.get("/loud/me", (c) => c.json(c.get("authState")));

    const headers = { Cookie: harness.jar.header() };

    const quiet = await app.request(`${testBaseUrl}/quiet/me`, { headers });
    expect(quiet.headers.get("set-cookie") ?? "").not.toContain(cookieName);
    // Auth state is still fully resolved; only the cookie write is suppressed.
    expect(await quiet.json()).toMatchObject({ authenticated: true, role: "owner" });

    const loud = await app.request(`${testBaseUrl}/loud/me`, { headers });
    expect(loud.headers.get("set-cookie") ?? "").toContain(cookieName);
  });
});

describe("provisioning self-heal", () => {
  it("provisions a default organization on the next request when the signup hook did not", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "selfheal@example.com", password: "correct-horse-battery" });

    const user = await harness.cfAuth.repository.findUserByEmail("selfheal@example.com");
    const [provisioned] = await harness.cfAuth.repository.listOrganizationsForUser(user!.id);

    // Wipe the org the create hook made, reproducing the state the user would
    // be in had that hook thrown (the membership cascades with the org row).
    await harness.client.execute({
      sql: "DELETE FROM organization WHERE id = ?",
      args: [provisioned!.organization.id],
    });
    expect(await harness.cfAuth.repository.listOrganizationsForUser(user!.id)).toEqual([]);

    // A plain authenticated request is enough to heal it.
    const state = await harness.me();

    expect(state.authenticated).toBe(true);
    expect(state.organization).not.toBeNull();
    expect(state.role).toBe("owner");
    expect(await harness.cfAuth.repository.listOrganizationsForUser(user!.id)).toHaveLength(1);
  });

  it("does not silently re-add a user to a default org they were removed from", async () => {
    const harness = await createTestAuth();
    const removed = await createUser(harness, "removed@example.com");
    const coOwner = await createUser(harness, "coowner@example.com");

    const [defaultOrg] = await harness.cfAuth.repository.listOrganizationsForUser(removed.id);
    const defaultOrgId = defaultOrg!.organization.id;

    // Hand the org to a second owner, then leave it.
    await harness.cfAuth.service.addOrganizationMember({
      actorUserId: removed.id,
      organizationId: defaultOrgId,
      userId: coOwner.id,
      role: "owner",
    });
    await harness.cfAuth.service.removeOrganizationMember({
      actorUserId: coOwner.id,
      organizationId: defaultOrgId,
      userId: removed.id,
    });

    expect(await harness.cfAuth.repository.listOrganizationsForUser(removed.id)).toEqual([]);

    // Re-provisioning must NOT put them back into the org they left.
    const state = await harness.cfAuth.service.getAuthState(removed.id, null);
    const healed = await harness.cfAuth.service.ensureDefaultOrganization(state!);

    expect(healed.organization).not.toBeNull();
    expect(healed.organization?.id).not.toBe(defaultOrgId);
    expect(healed.role).toBe("owner");
    expect(await harness.cfAuth.repository.findMembership(removed.id, defaultOrgId)).toBeNull();

    // The original org is untouched and still owned by the co-owner.
    expect(await harness.cfAuth.repository.countOrganizationOwners(defaultOrgId)).toBe(1);
  });
});
