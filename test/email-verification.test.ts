import { describe, expect, it } from "vitest";
import type { AuthUser } from "../src/types.js";
import { createTestAuth, testBaseUrl } from "./helpers.js";

describe("email verification", () => {
  it("sends a link on signup that verifies the address when opened", async () => {
    const sent: { user: AuthUser; url: string; token: string }[] = [];
    const harness = await createTestAuth({
      emailVerification: {
        send: async (input) => {
          sent.push(input);
        },
      },
    });

    await harness.signUp({ email: "verify-me@example.com", password: "correct-horse-battery" });
    // better-auth hands the send to the background; let it run.
    await new Promise((resolve) => setTimeout(resolve, 50));

    expect(sent).toHaveLength(1);
    expect(sent[0]!.user).toMatchObject({ email: "verify-me@example.com", emailVerified: false });
    const link = new URL(sent[0]!.url);
    expect(link.origin).toBe(testBaseUrl);
    expect(link.pathname).toBe(`${harness.cfAuth.basePath}/verify-email`);
    expect(link.searchParams.get("token")).toBe(sent[0]!.token);

    const response = await harness.request(`${link.pathname}${link.search}`);
    expect(response.status).toBeLessThan(400);

    const user = await harness.cfAuth.repository.findUserByEmail("verify-me@example.com");
    expect(user?.emailVerified).toBe(true);
    expect(harness.events).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ type: "user.email_verified", userId: user!.id }),
      ]),
    );
  });

  it("sends nothing while it is off", async () => {
    const harness = await createTestAuth();
    await harness.signUp({ email: "quiet@example.com", password: "correct-horse-battery" });
    const user = await harness.cfAuth.repository.findUserByEmail("quiet@example.com");
    expect(user?.emailVerified).toBe(false);
  });

  it("refuses a configuration without a sender", async () => {
    await expect(
      createTestAuth({
        emailVerification: { send: "nope" as unknown as () => Promise<void> },
      }),
    ).rejects.toMatchObject({ code: "validation_error" });
  });
});
