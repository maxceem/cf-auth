import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createCfAuth } from "../src/cf-auth.js";
import { resolveConfig } from "../src/config.js";
import { createCurrentOrganizationCookie, isSecureRequest } from "../src/cookies.js";
import { createTestAuth, testBaseUrl, testSecret } from "./helpers.js";

const organizationId = "11111111-2222-3333-4444-555555555555";

/** Minimal app exposing the cookie helpers so we can round-trip through HTTP. */
const createCookieApp = (secret: string) => {
  const config = resolveConfig({
    appName: "Cookie App",
    secret,
    // The cookie helpers never touch the database, but config requires one.
    db: {} as never,
  });
  const cookie = createCurrentOrganizationCookie(config);

  const app = new Hono();
  app.post("/write", async (c) => {
    await cookie.write(c, organizationId);
    return c.json({ ok: true });
  });
  app.get("/read", async (c) => c.json({ value: await cookie.read(c) }));
  app.post("/clear", (c) => {
    cookie.clear(c);
    return c.json({ ok: true });
  });

  return { app, cookie, config };
};

describe("current organization cookie", () => {
  it("round-trips a signed value", async () => {
    const { app, cookie } = createCookieApp(testSecret);

    const written = await app.request("http://localhost/write", { method: "POST" });
    const setCookie = written.headers.get("set-cookie")!;

    expect(setCookie).toContain(`${cookie.name}=`);
    expect(setCookie).toContain("HttpOnly");
    expect(setCookie).toContain("SameSite=Lax");
    // Signed, not plaintext: the raw org id must not be the whole cookie value.
    expect(setCookie.split(";")[0]).not.toBe(`${cookie.name}=${organizationId}`);

    const read = await app.request("http://localhost/read", {
      headers: { Cookie: setCookie.split(";")[0]! },
    });

    expect(await read.json()).toEqual({ value: organizationId });
  });

  it("rejects a tampered value", async () => {
    const { app, cookie } = createCookieApp(testSecret);

    const written = await app.request("http://localhost/write", { method: "POST" });
    const pair = written.headers.get("set-cookie")!.split(";")[0]!;
    const [, signed] = pair.split(/=(.*)/s);
    const tampered = `${cookie.name}=${encodeURIComponent(
      `evil-org.${decodeURIComponent(signed!).split(".")[1] ?? ""}`,
    )}`;

    const read = await app.request("http://localhost/read", { headers: { Cookie: tampered } });

    expect(await read.json()).toEqual({ value: null });
  });

  it("rejects a value signed with a different secret", async () => {
    const foreign = createCookieApp("a-completely-different-secret-value-000");
    const written = await foreign.app.request("http://localhost/write", { method: "POST" });
    const pair = written.headers.get("set-cookie")!.split(";")[0]!;

    const ours = createCookieApp(testSecret);
    const read = await ours.app.request("http://localhost/read", { headers: { Cookie: pair } });

    expect(await read.json()).toEqual({ value: null });
  });

  it("returns null when the cookie is absent", async () => {
    const { app } = createCookieApp(testSecret);
    const read = await app.request("http://localhost/read");
    expect(await read.json()).toEqual({ value: null });
  });

  it("clears the cookie", async () => {
    const { app, cookie } = createCookieApp(testSecret);
    const cleared = await app.request("http://localhost/clear", { method: "POST" });

    expect(cleared.headers.get("set-cookie")).toContain(`${cookie.name}=;`);
  });

  it("marks the cookie Secure only over https", async () => {
    const { app } = createCookieApp(testSecret);

    const insecure = await app.request("http://localhost/write", { method: "POST" });
    expect(insecure.headers.get("set-cookie")).not.toContain("Secure");

    const secure = await app.request("https://localhost/write", { method: "POST" });
    expect(secure.headers.get("set-cookie")).toContain("Secure");

    expect(isSecureRequest("https://example.com/x")).toBe(true);
    expect(isSecureRequest("http://example.com/x")).toBe(false);
  });

  it("is written by the middleware and honoured on the next request", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "cookie-flow@example.com", password: "correct-horse-battery" });

    const first = await harness.me();
    expect(harness.jar.has(harness.cfAuth.currentOrganizationCookie.name)).toBe(true);

    const user = await harness.cfAuth.repository.findUserByEmail("cookie-flow@example.com");
    const second = await harness.cfAuth.service.createOrganization(user!.id, "Second Org");

    // Explicitly switch by writing the cookie the way a route handler would.
    const app = new Hono();
    app.post("/switch", async (c) => {
      await harness.cfAuth.currentOrganizationCookie.write(c, second.organization.id);
      return c.json({ ok: true });
    });
    const switched = await app.request(`${testBaseUrl}/switch`, { method: "POST" });
    harness.jar.absorb(switched);

    const after = await harness.me();
    expect(first.organization?.id).not.toBe(second.organization.id);
    expect(after.organization?.id).toBe(second.organization.id);
    expect(after.role).toBe("owner");
  });

  it("is invalidated by a prefix change, then self-heals", async () => {
    const harness = await createTestAuth({ appName: "Before Rename" });
    await harness.signUp({ email: "rename@example.com", password: "correct-horse-battery" });

    const first = await harness.me();
    const oldCookieName = harness.cfAuth.currentOrganizationCookie.name;
    expect(oldCookieName).toBe("before_rename_current_organization");
    expect(harness.jar.has(oldCookieName)).toBe(true);

    // Same database and secret, different app name.
    const renamed = createCfAuth({
      appName: "After Rename",
      secret: testSecret,
      baseUrl: testBaseUrl,
      db: harness.db,
    });

    expect(renamed.currentOrganizationCookie.name).toBe("after_rename_current_organization");

    const app = new Hono();
    app.get("/read", async (c) => c.json({ value: await renamed.currentOrganizationCookie.read(c) }));

    // Neither the name nor the derived signing key carries over.
    const byOldName = await app.request(`${testBaseUrl}/read`, {
      headers: { Cookie: harness.jar.header() },
    });
    expect(await byOldName.json()).toEqual({ value: null });

    const renamedTo = `${renamed.currentOrganizationCookie.name}=${harness.jar.get(oldCookieName)}`;
    const byNewName = await app.request(`${testBaseUrl}/read`, { headers: { Cookie: renamedTo } });
    expect(await byNewName.json()).toEqual({ value: null });

    // Self-healing: the session still works and the org is re-selected.
    const healed = await harness.me();
    expect(healed.authenticated).toBe(true);
    expect(healed.organization?.id).toBe(first.organization?.id);
  });

  it("re-points the cookie at a valid org when it names one the user cannot access", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "stale@example.com", password: "correct-horse-battery" });
    await harness.me();

    const app = new Hono();
    app.post("/forge", async (c) => {
      // Correctly signed, but naming an organization the user is not in.
      await harness.cfAuth.currentOrganizationCookie.write(c, "99999999-0000-0000-0000-000000000000");
      return c.json({ ok: true });
    });
    harness.jar.absorb(await app.request(`${testBaseUrl}/forge`, { method: "POST" }));

    const state = await harness.me();

    expect(state.authenticated).toBe(true);
    expect(state.organization?.id).not.toBe("99999999-0000-0000-0000-000000000000");
    expect(state.role).toBe("owner");
  });
});
