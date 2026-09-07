import { describe, expect, it } from "vitest";
import { createTestAuth, testBaseUrl } from "./helpers.js";

describe("session resolution", () => {
  it("returns an empty auth state for anonymous requests", async () => {
    const harness = await createTestAuth();

    const state = await harness.me({ useJar: false });

    expect(state).toEqual({
      authenticated: false,
      credentialType: null,
      source: null,
      actor: null,
      user: null,
      memberships: [],
      organization: null,
      role: null,
    });
  });

  it("resolves user, organization, role and source from the session cookie", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "session@example.com", password: "correct-horse-battery" });

    const state = await harness.me();

    expect(state.authenticated).toBe(true);
    expect(state.credentialType).toBe("session");
    expect(state.source).toBe("web");
    expect(state.actor).toEqual({
      type: "user",
      id: state.user!.id,
      actionSource: "web",
    });
    expect(state.user?.email).toBe("session@example.com");
    expect(state.organization?.name).toBe("My Organization");
    expect(state.role).toBe("owner");
    expect(state.memberships).toHaveLength(1);
  });

  it("authenticates a fresh sign-in with email and password", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "login@example.com", password: "correct-horse-battery" });

    harness.jar.clear();
    expect((await harness.me()).authenticated).toBe(false);

    await harness.signIn({ email: "login@example.com", password: "correct-horse-battery" });
    const state = await harness.me();

    expect(state.authenticated).toBe(true);
    expect(state.user?.email).toBe("login@example.com");
    expect(state.organization).not.toBeNull();
  });

  it("rejects a wrong password", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "wrong@example.com", password: "correct-horse-battery" });
    harness.jar.clear();

    const response = await harness.request(`${harness.cfAuth.basePath}/sign-in/email`, {
      json: { email: "wrong@example.com", password: "not-the-password" },
    });

    expect(response.ok).toBe(false);
    expect((await harness.me()).authenticated).toBe(false);
  });

  it("clears the session on sign-out", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "bye@example.com", password: "correct-horse-battery" });
    expect((await harness.me()).authenticated).toBe(true);

    await harness.request(`${harness.cfAuth.basePath}/sign-out`, { json: {} });

    expect((await harness.me()).authenticated).toBe(false);
  });

  it("derives cookie names from the configured prefix, not a hard-coded app name", async () => {
    const harness = await createTestAuth({ appName: "Acme App" });
    await harness.signUp({ email: "prefix@example.com", password: "correct-horse-battery" });
    await harness.me();

    expect(harness.cfAuth.config.cookies.prefix).toBe("acme_app");
    expect(harness.cfAuth.config.cookies.betterAuthPrefix).toBe("acme_app_auth");
    expect(harness.cfAuth.currentOrganizationCookie.name).toBe("acme_app_current_organization");
    expect(harness.jar.has("acme_app_current_organization")).toBe(true);
    expect([...harness.jar.header().matchAll(/acme_app_auth\./g)].length).toBeGreaterThan(0);
  });

  it("accepts an explicit cookie prefix override", async () => {
    const harness = await createTestAuth({
      appName: "Acme App",
      cookies: { prefix: "acme", currentOrganizationCookieName: "acme_tenant" },
    });

    expect(harness.cfAuth.config.cookies.betterAuthPrefix).toBe("acme_auth");
    expect(harness.cfAuth.currentOrganizationCookie.name).toBe("acme_tenant");
  });

  it("mounts better-auth at the configured base path", async () => {
    const harness = await createTestAuth({ basePath: "/auth" });

    expect(harness.cfAuth.basePath).toBe("/auth");
    expect(harness.cfAuth.routePattern).toBe("/auth/*");

    const response = await harness.request("/auth/sign-up/email", {
      json: {
        email: "basepath@example.com",
        password: "correct-horse-battery",
        name: "Base Path",
      },
    });

    expect(response.ok).toBe(true);
  });

  it("exposes the raw better-auth fetch handler", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "raw@example.com", password: "correct-horse-battery" });

    const response = await harness.cfAuth.handler(
      new Request(`${testBaseUrl}${harness.cfAuth.basePath}/get-session`, {
        headers: { Cookie: harness.jar.header() },
      }),
    );

    expect(response.ok).toBe(true);
    const body = (await response.json()) as { user?: { email?: string } } | null;
    expect(body?.user?.email).toBe("raw@example.com");
  });
});
