import { describe, expect, it } from "vitest";
import { createTestSessions } from "../src/testing.js";
import { createTestAuth } from "./helpers.js";

describe("cf-auth/testing", () => {
  it("mints a session the middleware resolves exactly as a signed-in one", async () => {
    const harness = await createTestAuth();
    const sessions = createTestSessions(harness.cfAuth);

    const operator = await sessions.operator({ email: "minted@example.com" });
    const state = await harness.me({
      headers: { Cookie: operator.cookie },
      useJar: false,
    });

    expect(state.authenticated).toBe(true);
    expect(state.credentialType).toBe("session");
    expect(state.source).toBe("web");
    expect(state.user?.id).toBe(operator.userId);
    expect(state.user?.email).toBe("minted@example.com");
    expect(state.organization?.id).toBe(operator.organizationId);
    expect(state.role).toBe("owner");
  });

  it("gives each operator their own user and organization", async () => {
    const harness = await createTestAuth();
    const sessions = createTestSessions(harness.cfAuth);

    const [first, second] = [await sessions.operator(), await sessions.operator()];

    expect(first.userId).not.toBe(second.userId);
    expect(first.organizationId).not.toBe(second.organizationId);

    for (const operator of [first, second]) {
      const state = await harness.me({ headers: { Cookie: operator.cookie }, useJar: false });
      expect(state.organization?.id).toBe(operator.organizationId);
    }
  });

  /**
   * The guard that keeps the rest of this honest. `cookieFor` mirrors how
   * better-call signs a cookie rather than calling it — that function is not on
   * better-call's `exports` map — so this asserts the two agree. If better-auth
   * ever changes the cookie's name or its `value.signature` encoding, this
   * fails here, in the package that owns the knowledge, rather than in every
   * application that depends on it.
   */
  it("names and signs the cookie the way a real sign-up does", async () => {
    const harness = await createTestAuth();
    const signUp = await harness.signUp({
      email: "roundtrip@example.com",
      password: "correct-horse-battery",
    });
    const realCookie = (signUp.headers.get("set-cookie") ?? "").split(";")[0] ?? "";
    const [realName, realValue] = [realCookie.slice(0, realCookie.indexOf("=")), realCookie.slice(realCookie.indexOf("=") + 1)];

    const user = await harness.cfAuth.repository.findUserByEmail("roundtrip@example.com");
    const minted = await createTestSessions(harness.cfAuth).cookieFor(user!.id);
    const [mintedName, mintedValue] = [minted.slice(0, minted.indexOf("=")), minted.slice(minted.indexOf("=") + 1)];

    expect(mintedName).toBe(realName);
    // Same shape: a token and a signature, URL-encoded, differing only in the
    // token. Comparing the decoded halves keeps the failure readable.
    const halves = (value: string) => decodeURIComponent(value).split(".");
    expect(halves(mintedValue)).toHaveLength(halves(realValue).length);
    expect(halves(mintedValue)[1]).not.toBe(halves(realValue)[1]);
    expect(halves(mintedValue)[0]).not.toBe(halves(realValue)[0]);

    // And the real proof: the middleware accepts it.
    const state = await harness.me({ headers: { Cookie: minted }, useJar: false });
    expect(state.user?.id).toBe(user!.id);
  });

  it("signs a fresh token every time, so nothing is reusable between tests", async () => {
    const harness = await createTestAuth();
    const sessions = createTestSessions(harness.cfAuth);
    const operator = await sessions.operator();

    const [first, second] = [
      await sessions.cookieFor(operator.userId),
      await sessions.cookieFor(operator.userId),
    ];

    expect(first).not.toBe(second);
    for (const cookie of [first, second]) {
      expect((await harness.me({ headers: { Cookie: cookie }, useJar: false })).user?.id).toBe(
        operator.userId,
      );
    }
  });
});
